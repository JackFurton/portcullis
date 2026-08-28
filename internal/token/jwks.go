// Package token verifies JWTs against the key sets published by the issuers
// the policy trusts.
package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/JackFurton/portcullis/internal/metrics"
	"github.com/JackFurton/portcullis/internal/policy"
)

// maxJWKSBytes bounds a key set response. A JWKS is a few kilobytes; anything
// approaching this is either a misconfigured URL or someone feeding the
// gateway a decompression bomb.
const maxJWKSBytes = 1 << 20

// minMissRefetchInterval is the floor between two refetches triggered by a
// token whose kid is not in the cached set.
//
// Without it, a token carrying a random kid forces a fetch, and a few hundred
// of those per second turn this service into a denial of service against the
// identity provider, with the gateway as the amplifier. The floor applies only
// to miss-triggered refetches, so the first token signed with a freshly
// rotated key still causes an immediate refetch and works right away.
const minMissRefetchInterval = 15 * time.Second

// ErrUnknownKey means no key in the issuer's set matches the token's kid.
var ErrUnknownKey = errors.New("no matching signing key")

// KeyCache holds the key set for each configured issuer.
type KeyCache struct {
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*keyEntry
}

type keyEntry struct {
	// mu serializes fetches for one issuer, so a burst of requests arriving
	// after a key rotation produces one fetch rather than one per request.
	mu sync.Mutex

	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	lastErr   error

	// lastMissRefetch is when an unknown kid last caused a refetch. Scheduled
	// and startup fetches do not touch it: they are not attacker triggered,
	// and counting them would delay picking up a rotation.
	lastMissRefetch time.Time
}

// NewKeyCache builds a cache. The client should have a timeout: a JWKS
// endpoint that accepts the connection and never answers would otherwise hold
// a request thread for as long as it likes.
func NewKeyCache(client *http.Client, log *slog.Logger) *KeyCache {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &KeyCache{
		client:  client,
		log:     log,
		now:     time.Now,
		entries: map[string]*keyEntry{},
	}
}

// Keys returns the candidate keys for a token.
//
// A token with a kid gets the keys with that kid. A token without one gets
// every key in the set, which is correct but slower, and is why issuers are
// expected to publish a kid.
func (c *KeyCache) Keys(ctx context.Context, issuer *policy.Issuer, kid string) ([]jose.JSONWebKey, error) {
	entry := c.entry(issuer.Name)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.keys == nil || c.stale(entry, issuer) {
		if err := c.fetchLocked(ctx, issuer, entry); err != nil && entry.keys == nil {
			return nil, err
		}
	}

	keys := selectKeys(entry.keys, kid)
	if len(keys) > 0 {
		return keys, nil
	}

	// An unknown kid usually means the issuer rotated. Refetch, but not more
	// often than the floor allows.
	if c.now().Sub(entry.lastMissRefetch) >= minMissRefetchInterval {
		entry.lastMissRefetch = c.now()
		if err := c.fetchLocked(ctx, issuer, entry); err != nil {
			return nil, fmt.Errorf("%w for kid %q: %w", ErrUnknownKey, kid, err)
		}
		keys = selectKeys(entry.keys, kid)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w for kid %q", ErrUnknownKey, kid)
	}
	return keys, nil
}

// Warm fetches the key set for each configured issuer, so the first real
// request does not pay for it. Failures are logged, not fatal: an issuer that
// is down at startup should not stop the gateway from serving the rules that
// do not need it.
func (c *KeyCache) Warm(ctx context.Context, config *policy.Config) {
	for i := range config.Issuers {
		issuer := &config.Issuers[i]
		entry := c.entry(issuer.Name)
		entry.mu.Lock()
		err := c.fetchLocked(ctx, issuer, entry)
		entry.mu.Unlock()
		if err != nil {
			c.log.Warn("could not load key set at startup", "issuer", issuer.Name, "error", err)
		}
	}
}

// Refresh periodically refetches every key set, so a rotation is picked up
// before a token signed with the new key arrives.
func (c *KeyCache) Refresh(ctx context.Context, store *policy.Store) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		config := store.Config()
		for i := range config.Issuers {
			issuer := &config.Issuers[i]
			entry := c.entry(issuer.Name)

			entry.mu.Lock()
			due := c.now().Sub(entry.fetchedAt) >= issuer.RefreshInterval.Or(policy.DefaultRefreshInterval)
			if due {
				if err := c.fetchLocked(ctx, issuer, entry); err != nil {
					c.log.Warn("key set refresh failed, serving the cached set",
						"issuer", issuer.Name, "error", err)
				}
			}
			entry.mu.Unlock()
		}
	}
}

// stale reports whether the cached set has aged past its TTL.
func (c *KeyCache) stale(entry *keyEntry, issuer *policy.Issuer) bool {
	return c.now().Sub(entry.fetchedAt) > issuer.CacheTTL.Or(policy.DefaultCacheTTL)
}

// fetchLocked replaces the cached set. The caller holds entry.mu.
//
// On failure the previous set is kept. Denying every request because the
// identity provider is having an outage makes their incident into yours, and
// the keys almost certainly have not changed in the meantime.
func (c *KeyCache) fetchLocked(ctx context.Context, issuer *policy.Issuer, entry *keyEntry) error {
	keys, err := c.fetch(ctx, issuer.JWKSURL)
	if err != nil {
		metrics.JWKSFetches.WithLabelValues(issuer.Name, "error").Inc()
		entry.lastErr = err
		return err
	}
	metrics.JWKSFetches.WithLabelValues(issuer.Name, "success").Inc()
	entry.keys = keys
	entry.fetchedAt = c.now()
	entry.lastErr = nil
	c.log.Info("loaded key set", "issuer", issuer.Name, "keys", len(keys.Keys))
	return nil
}

func (c *KeyCache) fetch(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("JWKS is larger than %d bytes", maxJWKSBytes)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	return &set, nil
}

func (c *KeyCache) entry(name string) *keyEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[name]
	if !ok {
		entry = &keyEntry{}
		c.entries[name] = entry
	}
	return entry
}

// selectKeys returns the usable verification keys, filtered by kid when the
// token carries one.
//
// Keys marked for encryption are skipped. Verifying a signature with a key the
// issuer published for encryption is exactly the kind of cross-purpose reuse
// the "use" field exists to prevent.
func selectKeys(set *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if set == nil {
		return nil
	}
	out := make([]jose.JSONWebKey, 0, len(set.Keys))
	for _, key := range set.Keys {
		if key.Use == "enc" {
			continue
		}
		if !key.IsPublic() {
			// A private key in a published key set is a mistake on the
			// issuer's side. Using it would still verify, but treating the
			// document as public material only is the safer read.
			continue
		}
		if kid != "" && key.KeyID != kid {
			continue
		}
		out = append(out, key)
	}
	return out
}
