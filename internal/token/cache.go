package token

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultCacheSize is how many verified tokens are remembered. Each entry is a
// small struct plus the identity, so ten thousand of them is a few megabytes.
const DefaultCacheSize = 10000

// maxCacheAge bounds how long a verification result is reused, independently
// of how long the token itself is valid.
//
// Expiry is still enforced exactly on every hit, so this is not about letting
// dead tokens through. It bounds how stale the rest of the decision can be:
// the issuer's configuration could have changed, or a key could have been
// pulled, and a token with an eight hour lifetime should not coast on a result
// computed at the start of it.
const maxCacheAge = 60 * time.Second

// verifiedCache remembers recently verified tokens.
//
// Signature verification is the expensive part of a decision, and a caller
// reuses one token for its whole lifetime. Without this, a service handling a
// thousand requests a second does a thousand RSA verifications a second, all
// with the same answer.
//
// The key is a hash of the token, never the token itself: this map is the kind
// of thing that ends up in a heap dump.
type verifiedCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
	max     int
}

type cacheEntry struct {
	key      string
	identity *Identity
	// verifiedAt is when the signature was actually checked, which bounds
	// reuse independently of the token's own expiry.
	verifiedAt time.Time
}

// newVerifiedCache builds a cache holding at most max entries. A max of zero
// disables caching, which is a legitimate choice for a deployment that would
// rather pay for a verification than hold identities in memory at all.
func newVerifiedCache(max int) *verifiedCache {
	if max < 0 {
		max = DefaultCacheSize
	}
	return &verifiedCache{
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
		max:     max,
	}
}

// cacheKey binds a result to the issuer it was verified against, so the same
// raw token cannot be reused across two issuer configurations.
func cacheKey(issuerName, raw string) string {
	sum := sha256.Sum256([]byte(issuerName + "\x00" + raw))
	return hex.EncodeToString(sum[:])
}

// get returns a cached identity if one is still usable.
func (c *verifiedCache) get(key string, now time.Time, skew time.Duration) (*Identity, bool) {
	if c.max == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*cacheEntry)

	// Expiry is checked on every hit rather than at insertion, so a cached
	// result never outlives the token it came from.
	if now.After(entry.identity.ExpiresAt.Add(skew)) || now.Sub(entry.verifiedAt) > maxCacheAge {
		c.removeLocked(element)
		return nil, false
	}

	c.order.MoveToFront(element)
	return entry.identity, true
}

// put records a verified identity, evicting the least recently used entry when
// the cache is full. The bound is what keeps a flood of distinct tokens from
// turning this into a memory exhaustion bug.
func (c *verifiedCache) put(key string, identity *Identity, now time.Time) {
	if c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.identity, entry.verifiedAt = identity, now
		c.order.MoveToFront(element)
		return
	}

	element := c.order.PushFront(&cacheEntry{key: key, identity: identity, verifiedAt: now})
	c.entries[key] = element

	for c.order.Len() > c.max {
		c.removeLocked(c.order.Back())
	}
}

// Flush drops every entry. It runs on policy reload, because a reload can
// change an issuer's audiences, algorithms or claim mapping, and a result
// computed under the old configuration says nothing about the new one.
func (c *verifiedCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*list.Element, c.max)
	c.order.Init()
}

// Len reports how many results are cached.
func (c *verifiedCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *verifiedCache) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	c.order.Remove(element)
	delete(c.entries, element.Value.(*cacheEntry).key)
}
