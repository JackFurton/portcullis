// Package policy holds the authorization rules the service evaluates and the
// issuers it will accept tokens from.
//
// The configuration is a file rather than a custom resource on purpose. This
// service sits in the request path of every call through the mesh, and a file
// it can validate fully at load time, reload atomically, and refuse to apply
// when broken is a smaller blast radius than a CRD an admission webhook may or
// may not have checked.
package policy

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// FailureMode decides what happens when a decision cannot be reached: the JWKS
// endpoint is unreachable, a rule references an issuer that failed to load, or
// the service panics on a malformed request.
type FailureMode string

const (
	// FailClosed denies the request. This is the default, and the only value
	// that makes sense for a service whose job is to say no.
	FailClosed FailureMode = "deny"
	// FailOpen allows the request through. It exists because someone will ask
	// for it during an incident, and a documented switch is better than a
	// hurried patch that removes the filter entirely.
	FailOpen FailureMode = "allow"
)

// Config is the whole policy.
type Config struct {
	// FailureMode decides what an internal error means. Defaults to deny.
	FailureMode FailureMode `json:"failureMode,omitempty"`

	// Issuers are the token issuers this service trusts. A token from an
	// issuer that is not listed here is never valid, regardless of signature.
	Issuers []Issuer `json:"issuers,omitempty"`

	// Rules are evaluated in order and the first match decides. Anything that
	// matches no rule is denied, so the policy never has to spell out a final
	// catch-all and nobody can delete it by accident.
	Rules []Rule `json:"rules"`

	// ForwardPrefix is the header prefix used for the identity this service
	// hands downstream. Every header with this prefix is stripped from the
	// inbound request first, so a client cannot forge its own identity.
	ForwardPrefix string `json:"forwardPrefix,omitempty"`
}

// Issuer describes a trusted token issuer.
type Issuer struct {
	// Name identifies the issuer inside this file. Rules refer to it by name.
	Name string `json:"name"`

	// Issuer is the exact value the token's iss claim must equal.
	Issuer string `json:"issuer"`

	// JWKSURL is where the signing keys are published. It is required: this
	// service does not discover it from the issuer, because that turns every
	// token into a request to an attacker-controlled URL if iss is ever
	// trusted before it is verified.
	JWKSURL string `json:"jwksURL"`

	// Audiences the aud claim must contain at least one of.
	Audiences []string `json:"audiences"`

	// Algorithms the token header alg must be one of. There is no default of
	// "whatever the key supports": an explicit list is what stops a token
	// signed with HS256 against the public key from being accepted as if it
	// were RS256.
	Algorithms []string `json:"algorithms"`

	// TenantClaim names the claim carrying the tenant identifier.
	TenantClaim string `json:"tenantClaim,omitempty"`

	// ScopeClaim names the claim carrying scopes. Both the space delimited
	// string form and the array form are understood.
	ScopeClaim string `json:"scopeClaim,omitempty"`

	// ForwardClaims are extra claims copied into headers for the upstream.
	ForwardClaims []string `json:"forwardClaims,omitempty"`

	// ClockSkew is the tolerance applied to exp, nbf and iat.
	ClockSkew Duration `json:"clockSkew,omitempty"`

	// RefreshInterval is how often the key set is refetched in the background.
	RefreshInterval Duration `json:"refreshInterval,omitempty"`

	// CacheTTL is how long a fetched key set is served before it is considered
	// stale. A stale set is still used if the refresh is failing, because
	// denying every request over a temporarily unreachable JWKS endpoint turns
	// an issuer's outage into yours.
	CacheTTL Duration `json:"cacheTTL,omitempty"`
}

// Rule is one entry in the ordered policy.
type Rule struct {
	// Name appears in logs, metrics and dynamic metadata.
	Name string `json:"name"`

	// Match selects the requests this rule applies to. An empty Match matches
	// every request, which is only useful as the last rule.
	Match Match `json:"match,omitempty"`

	// Allow states what an allowed request must carry. A rule with no Allow
	// block denies everything it matches, which is how a deny rule is written.
	Allow *Allow `json:"allow,omitempty"`
}

// Match selects requests. Every field that is set must match; within a field,
// any value matching is enough.
type Match struct {
	// Hosts the :authority header must equal, port stripped. A leading "*."
	// matches one or more leading labels.
	Hosts []string `json:"hosts,omitempty"`

	// Methods the request method must be one of.
	Methods []string `json:"methods,omitempty"`

	// PathPrefixes the normalized path must start with. A prefix ending in "/"
	// matches path segments; a prefix that does not is still required to end
	// at a segment boundary, so /v1/admin does not match /v1/administrators.
	PathPrefixes []string `json:"pathPrefixes,omitempty"`

	// PathsExact the normalized path must equal.
	PathsExact []string `json:"pathsExact,omitempty"`
}

// Allow states the conditions for permitting a matched request.
type Allow struct {
	// Public permits the request with no token at all.
	//
	// A token that is present is still verified, and a valid one is forwarded
	// as identity, so an endpoint can be open while still knowing who is
	// calling when it can. A token that fails verification does not turn the
	// request into a denial: that would make a public endpoint an oracle for
	// whether a forged token validates.
	Public bool `json:"public,omitempty"`

	// Issuers the token must have come from, by name. Empty means any
	// configured issuer.
	Issuers []string `json:"issuers,omitempty"`

	// Scopes the token must carry. All of them, not any: a rule that lists two
	// scopes is asking for both.
	Scopes []string `json:"scopes,omitempty"`

	// Tenants the token's tenant claim must be one of. The single entry "*"
	// means any non-empty tenant, which is different from an empty list: the
	// empty list does not look at the tenant at all.
	Tenants []string `json:"tenants,omitempty"`

	// Subjects the token's sub claim must be one of, for the rare rule that
	// pins a single machine identity.
	Subjects []string `json:"subjects,omitempty"`
}

// AnyTenant is the Tenants entry meaning "a tenant is required, any value".
const AnyTenant = "*"

// DefaultForwardPrefix is the header prefix used when the config omits one.
const DefaultForwardPrefix = "x-portcullis-"

// Duration is a time.Duration that unmarshals from a string like "30s".
type Duration time.Duration

// UnmarshalJSON parses a Go duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	text := strings.Trim(string(data), `"`)
	if text == "" || text == "null" {
		return nil
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// Or returns the duration, or fallback when it is unset.
func (d Duration) Or(fallback time.Duration) time.Duration {
	if d == 0 {
		return fallback
	}
	return time.Duration(d)
}

// Defaults for issuer timing. They are deliberately short enough that a
// revoked key stops working the same day and long enough that a busy gateway
// is not refetching a key set every few seconds.
const (
	DefaultClockSkew       = 30 * time.Second
	DefaultRefreshInterval = 15 * time.Minute
	DefaultCacheTTL        = time.Hour
)

// supportedAlgorithms is the allowlist. Symmetric algorithms are absent on
// purpose: a shared secret is not something a JWKS endpoint should be handing
// out, and accepting HS256 alongside RS256 is the classic way an attacker
// signs their own token with the public key.
var supportedAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// Validate checks the config and fills in defaults. A config that does not
// validate is never applied, on load or on reload.
func (c *Config) Validate() error {
	var errs []error

	switch c.FailureMode {
	case "":
		c.FailureMode = FailClosed
	case FailClosed, FailOpen:
	default:
		errs = append(errs, fmt.Errorf("failureMode %q must be %q or %q", c.FailureMode, FailClosed, FailOpen))
	}

	if c.ForwardPrefix == "" {
		c.ForwardPrefix = DefaultForwardPrefix
	}
	c.ForwardPrefix = strings.ToLower(c.ForwardPrefix)
	if !strings.HasSuffix(c.ForwardPrefix, "-") {
		errs = append(errs, fmt.Errorf("forwardPrefix %q must end in a dash", c.ForwardPrefix))
	}

	names := map[string]bool{}
	for i := range c.Issuers {
		issuer := &c.Issuers[i]
		if err := issuer.validate(); err != nil {
			errs = append(errs, fmt.Errorf("issuer %d (%s): %w", i, issuer.Name, err))
			continue
		}
		if names[issuer.Name] {
			errs = append(errs, fmt.Errorf("issuer name %q is used more than once", issuer.Name))
		}
		names[issuer.Name] = true
	}

	if len(c.Rules) == 0 {
		errs = append(errs, errors.New("no rules: every request would be denied"))
	}
	ruleNames := map[string]bool{}
	for i := range c.Rules {
		rule := &c.Rules[i]
		if err := rule.validate(names); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, rule.Name, err))
		}
		if ruleNames[rule.Name] {
			errs = append(errs, fmt.Errorf("rule name %q is used more than once", rule.Name))
		}
		ruleNames[rule.Name] = true
	}

	return errors.Join(errs...)
}

func (i *Issuer) validate() error {
	var errs []error
	if i.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if i.Issuer == "" {
		errs = append(errs, errors.New("issuer is required"))
	}
	switch {
	case i.JWKSURL == "":
		errs = append(errs, errors.New("jwksURL is required"))
	case !strings.HasPrefix(i.JWKSURL, "https://") && !strings.HasPrefix(i.JWKSURL, "http://"):
		errs = append(errs, fmt.Errorf("jwksURL %q must be an http or https URL", i.JWKSURL))
	}
	if len(i.Audiences) == 0 {
		// A token with no audience check is valid at every service that trusts
		// the issuer, which makes one compromised upstream enough to reach all
		// of them.
		errs = append(errs, errors.New("audiences is required"))
	}
	if len(i.Algorithms) == 0 {
		errs = append(errs, errors.New("algorithms is required"))
	}
	for _, alg := range i.Algorithms {
		if !slices.Contains(supportedAlgorithms, alg) {
			errs = append(errs, fmt.Errorf("algorithm %q is not supported (want one of %s)",
				alg, strings.Join(supportedAlgorithms, ", ")))
		}
	}
	return errors.Join(errs...)
}

func (r *Rule) validate(issuers map[string]bool) error {
	var errs []error
	if r.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	for _, method := range r.Match.Methods {
		if method != strings.ToUpper(method) {
			errs = append(errs, fmt.Errorf("method %q must be upper case", method))
		}
		if !validMethod(method) {
			errs = append(errs, fmt.Errorf("method %q is not a known HTTP method", method))
		}
	}
	for _, path := range append(slices.Clone(r.Match.PathPrefixes), r.Match.PathsExact...) {
		if !strings.HasPrefix(path, "/") {
			errs = append(errs, fmt.Errorf("path %q must start with a slash", path))
		}
	}
	if r.Allow == nil {
		return errors.Join(errs...)
	}
	for _, name := range r.Allow.Issuers {
		if !issuers[name] {
			errs = append(errs, fmt.Errorf("allow.issuers references unknown issuer %q", name))
		}
	}
	if r.Allow.Public && (len(r.Allow.Scopes) > 0 || len(r.Allow.Tenants) > 0 || len(r.Allow.Subjects) > 0) {
		// A public rule that also demands scopes reads as "authenticated" but
		// behaves as "anyone", which is the kind of ambiguity that ends up in
		// an incident review.
		errs = append(errs, errors.New("allow.public cannot be combined with scopes, tenants or subjects"))
	}
	return errors.Join(errs...)
}

func validMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// IssuerByName looks up a configured issuer by its name.
func (c *Config) IssuerByName(name string) (*Issuer, bool) {
	for i := range c.Issuers {
		if c.Issuers[i].Name == name {
			return &c.Issuers[i], true
		}
	}
	return nil, false
}

// IssuerByURL looks up a configured issuer by the value of its iss claim.
func (c *Config) IssuerByURL(url string) (*Issuer, bool) {
	for i := range c.Issuers {
		if c.Issuers[i].Issuer == url {
			return &c.Issuers[i], true
		}
	}
	return nil, false
}
