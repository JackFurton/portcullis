package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/JackFurton/portcullis/internal/metrics"
	"github.com/JackFurton/portcullis/internal/policy"
)

// Reasons a token is rejected. They are separate errors because they become
// the reason label on the deny metric, and "why is everything 401" is only
// answerable if the answer is more specific than "invalid token".
var (
	ErrMalformed      = errors.New("token is malformed")
	ErrBadSignature   = errors.New("signature does not verify")
	ErrWrongIssuer    = errors.New("issuer claim does not match")
	ErrWrongAudience  = errors.New("audience claim does not match")
	ErrExpired        = errors.New("token has expired")
	ErrNotYetValid    = errors.New("token is not valid yet")
	ErrMissingExpiry  = errors.New("token has no expiry")
	ErrUnsafeClaim    = errors.New("claim value is not safe to forward")
	ErrMissingSubject = errors.New("token has no subject")
)

// Identity is what a verified token says about the caller.
type Identity struct {
	// IssuerName is the name the policy gave this issuer.
	IssuerName string
	// Issuer is the iss claim.
	Issuer string
	// Subject is the sub claim.
	Subject string
	// Tenant is the value of the issuer's configured tenant claim.
	Tenant string
	// Scopes are the scopes the token carries.
	Scopes []string
	// Forwarded holds the extra claims the issuer config asked to pass on.
	Forwarded map[string]string
	// ExpiresAt is when the token stops being valid.
	ExpiresAt time.Time
}

// Verifier checks tokens against an issuer's published keys.
type Verifier struct {
	keys  *KeyCache
	cache *verifiedCache
	now   func() time.Time
}

// NewVerifier builds a Verifier over a key cache. cacheSize is how many
// verification results to remember; zero disables the cache and pays for a
// full signature check on every request.
func NewVerifier(keys *KeyCache, cacheSize int) *Verifier {
	return &Verifier{keys: keys, cache: newVerifiedCache(cacheSize), now: time.Now}
}

// Flush drops every cached verification result. Call it when the policy
// changes: a result computed under the old issuer configuration says nothing
// about the new one.
func (v *Verifier) Flush() { v.cache.Flush() }

// Cached reports how many verification results are held, for the metric.
func (v *Verifier) Cached() int { return v.cache.Len() }

// maxTokenBytes bounds the raw token. A JWT is a couple of kilobytes; a
// megabyte of base64 is someone probing for a parser that allocates first and
// checks later.
const maxTokenBytes = 16 << 10

// Verify checks a raw compact JWS against one issuer and returns what it says.
//
// The order matters. The signature is checked before any claim is read, and
// the algorithm allowlist is applied before the signature, so a token can
// never steer its own verification. In particular the iss claim is not used to
// choose the key set: the caller picks the issuer, and iss only has to agree.
func (v *Verifier) Verify(ctx context.Context, issuer *policy.Issuer, raw string) (*Identity, error) {
	if raw == "" || len(raw) > maxTokenBytes {
		return nil, fmt.Errorf("%w: empty or oversized", ErrMalformed)
	}

	skew := issuer.ClockSkew.Or(policy.DefaultClockSkew)
	key := cacheKey(issuer.Name, raw)
	if identity, ok := v.cache.get(key, v.now(), skew); ok {
		metrics.TokenCache.WithLabelValues("hit").Inc()
		return identity, nil
	}
	metrics.TokenCache.WithLabelValues("miss").Inc()

	algorithms := make([]jose.SignatureAlgorithm, 0, len(issuer.Algorithms))
	for _, alg := range issuer.Algorithms {
		algorithms = append(algorithms, jose.SignatureAlgorithm(alg))
	}

	// Passing the allowlist to the parser is what rejects alg "none" and the
	// HS256-signed-with-the-public-key trick, before any key is even looked up.
	parsed, err := jose.ParseSigned(raw, algorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(parsed.Signatures) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature, got %d", ErrMalformed, len(parsed.Signatures))
	}

	header := parsed.Signatures[0].Header
	candidates, err := v.keys.Keys(ctx, issuer, header.KeyID)
	if err != nil {
		return nil, err
	}

	payload, err := verifyAny(parsed, candidates)
	if err != nil {
		return nil, err
	}

	identity, err := v.claims(issuer, payload)
	if err != nil {
		// Only successes are cached. Caching a rejection would mean a token
		// that failed while the issuer's keys were briefly unreachable keeps
		// failing after they come back.
		return nil, err
	}
	v.cache.put(key, identity, v.now())
	return identity, nil
}

// verifyAny tries each candidate key and returns the payload from the first
// that verifies.
func verifyAny(parsed *jose.JSONWebSignature, keys []jose.JSONWebKey) ([]byte, error) {
	for i := range keys {
		payload, err := parsed.Verify(keys[i])
		if err == nil {
			return payload, nil
		}
	}
	return nil, ErrBadSignature
}

// registered is the subset of the standard claims this service checks.
type registered struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ExpiresAt *epoch   `json:"exp"`
	NotBefore *epoch   `json:"nbf"`
	IssuedAt  *epoch   `json:"iat"`
}

// claims validates the payload and extracts the identity.
func (v *Verifier) claims(issuer *policy.Issuer, payload []byte) (*Identity, error) {
	var std registered
	if err := json.Unmarshal(payload, &std); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	if std.Issuer != issuer.Issuer {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrWrongIssuer, std.Issuer, issuer.Issuer)
	}
	if !audienceAccepted(std.Audience, issuer.Audiences) {
		return nil, fmt.Errorf("%w: got %v, want one of %v", ErrWrongAudience, []string(std.Audience), issuer.Audiences)
	}
	if std.Subject == "" {
		return nil, ErrMissingSubject
	}

	skew := issuer.ClockSkew.Or(policy.DefaultClockSkew)
	now := v.now()

	// A token with no expiry never stops being valid, which makes revocation
	// impossible. Requiring exp is stricter than the spec and correct here.
	if std.ExpiresAt == nil {
		return nil, ErrMissingExpiry
	}
	if now.After(std.ExpiresAt.Time().Add(skew)) {
		return nil, fmt.Errorf("%w at %s", ErrExpired, std.ExpiresAt.Time().UTC().Format(time.RFC3339))
	}
	if std.NotBefore != nil && now.Before(std.NotBefore.Time().Add(-skew)) {
		return nil, fmt.Errorf("%w until %s", ErrNotYetValid, std.NotBefore.Time().UTC().Format(time.RFC3339))
	}
	if std.IssuedAt != nil && now.Before(std.IssuedAt.Time().Add(-skew)) {
		return nil, fmt.Errorf("%w: issued at %s", ErrNotYetValid, std.IssuedAt.Time().UTC().Format(time.RFC3339))
	}

	identity := &Identity{
		IssuerName: issuer.Name,
		Issuer:     std.Issuer,
		Subject:    std.Subject,
		ExpiresAt:  std.ExpiresAt.Time(),
		Forwarded:  map[string]string{},
	}

	if issuer.TenantClaim != "" {
		tenant, err := stringClaim(all, issuer.TenantClaim)
		if err != nil {
			return nil, err
		}
		identity.Tenant = tenant
	}
	if issuer.ScopeClaim != "" {
		scopes, err := scopeClaim(all, issuer.ScopeClaim)
		if err != nil {
			return nil, err
		}
		identity.Scopes = scopes
	}
	for _, name := range issuer.ForwardClaims {
		value, err := stringClaim(all, name)
		if err != nil {
			return nil, err
		}
		if value != "" {
			identity.Forwarded[name] = value
		}
	}

	// The subject ends up in a header too, so it gets the same check as
	// anything else copied out of the token.
	if err := safeHeaderValue(identity.Subject); err != nil {
		return nil, err
	}
	return identity, nil
}

// HasScopes reports whether the identity carries all of the required scopes.
func (i *Identity) HasScopes(required []string) bool {
	for _, scope := range required {
		if !slices.Contains(i.Scopes, scope) {
			return false
		}
	}
	return true
}

// audience unmarshals the aud claim, which is a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

func audienceAccepted(got audience, want []string) bool {
	for _, value := range got {
		if slices.Contains(want, value) {
			return true
		}
	}
	return false
}

// epoch unmarshals a NumericDate, which JSON encodes as seconds since the
// epoch and which some issuers emit with a fractional part.
type epoch float64

func (e *epoch) UnmarshalJSON(data []byte) error {
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("timestamp must be a number of seconds")
	}
	*e = epoch(seconds)
	return nil
}

func (e *epoch) Time() time.Time {
	seconds, fraction := float64(*e), 0.0
	whole := int64(seconds)
	fraction = seconds - float64(whole)
	return time.Unix(whole, int64(fraction*float64(time.Second)))
}

// stringClaim reads a claim that has to end up in a header. Numbers and
// booleans are rendered rather than rejected, because tenant identifiers are
// often numeric.
func stringClaim(claims map[string]any, name string) (string, error) {
	value, ok := claims[name]
	if !ok || value == nil {
		return "", nil
	}
	var text string
	switch v := value.(type) {
	case string:
		text = v
	case float64:
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		text = strconv.FormatBool(v)
	default:
		return "", fmt.Errorf("%w: claim %q is not a scalar", ErrUnsafeClaim, name)
	}
	if err := safeHeaderValue(text); err != nil {
		return "", fmt.Errorf("claim %q: %w", name, err)
	}
	return text, nil
}

// scopeClaim reads scopes, which appear either as a space delimited string
// (the OAuth 2 "scope" claim) or as an array (the "scp" and "permissions"
// claims various issuers use).
func scopeClaim(claims map[string]any, name string) ([]string, error) {
	value, ok := claims[name]
	if !ok || value == nil {
		return nil, nil
	}
	switch v := value.(type) {
	case string:
		return strings.Fields(v), nil
	case []any:
		scopes := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: claim %q contains a non-string scope", ErrUnsafeClaim, name)
			}
			scopes = append(scopes, text)
		}
		return scopes, nil
	default:
		return nil, fmt.Errorf("%w: claim %q is neither a string nor an array", ErrUnsafeClaim, name)
	}
}

// safeHeaderValue rejects anything that cannot go into an HTTP header.
//
// These values come from a token, which is signed but not necessarily written
// carefully. A newline in a claim that this service copies into a header is a
// response splitting bug handed to whatever is downstream.
func safeHeaderValue(value string) error {
	if len(value) > 1024 {
		return fmt.Errorf("%w: longer than 1024 bytes", ErrUnsafeClaim)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: contains a control character", ErrUnsafeClaim)
		}
	}
	return nil
}
