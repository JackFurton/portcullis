package policy_test

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JackFurton/portcullis/internal/policy"
)

func TestNormalizePathRejectsAmbiguity(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
		err  bool
	}{
		{name: "plain", path: "/v1/events", want: "/v1/events"},
		{name: "query is not part of the path", path: "/v1/events?since=1", want: "/v1/events"},
		{name: "fragment is dropped", path: "/v1/events#top", want: "/v1/events"},
		{name: "percent encoding is decoded", path: "/v1/events/a%20b", want: "/v1/events/a b"},

		// Each of these is a way for the path a rule matched to differ from
		// the path the upstream routes on.
		{name: "encoded slash", path: "/v1/public/%2f..%2fadmin", err: true},
		{name: "upper case encoded slash", path: "/v1/public/%2F..%2Fadmin", err: true},
		{name: "encoded backslash", path: "/v1%5cadmin", err: true},
		{name: "dot dot segment", path: "/v1/public/../admin", err: true},
		{name: "single dot segment", path: "/v1/./admin", err: true},
		{name: "encoded dot dot", path: "/v1/public/%2e%2e/admin", err: true},
		{name: "empty segment", path: "/v1//admin", err: true},
		{name: "backslash", path: `/v1\admin`, err: true},
		{name: "bad percent encoding", path: "/v1/%zz", err: true},
		{name: "relative", path: "v1/events", err: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.NormalizePath(tc.path)
			if tc.err {
				if !errors.Is(err, policy.ErrMalformedPath) {
					t.Fatalf("NormalizePath(%q) = %q, %v; want a malformed path error", tc.path, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePath(%q): %v", tc.path, err)
			}
			if got != tc.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func testConfig(t *testing.T, rules ...policy.Rule) *policy.Config {
	t.Helper()
	config := &policy.Config{Rules: rules}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return config
}

// A prefix has to end at a segment boundary. Without that, a rule guarding
// /v1/admin also matches /v1/administrators, and worse, a rule allowing
// /v1/public matches /v1/publicadmin.
func TestPrefixMatchStopsAtSegmentBoundaries(t *testing.T) {
	config := testConfig(t, policy.Rule{
		Name:  "admin",
		Match: policy.Match{PathPrefixes: []string{"/v1/admin"}},
		Allow: &policy.Allow{Public: true},
	})

	tests := []struct {
		path  string
		match bool
	}{
		{"/v1/admin", true},
		{"/v1/admin/", true},
		{"/v1/admin/users", true},
		{"/v1/administrators", false},
		{"/v1/admins", false},
		{"/v1/adm", false},
	}
	for _, tc := range tests {
		_, ok := config.Match(policy.Request{Method: "GET", Path: tc.path}, tc.path)
		if ok != tc.match {
			t.Errorf("path %q matched = %v, want %v", tc.path, ok, tc.match)
		}
	}
}

func TestMatchOrderDecides(t *testing.T) {
	config := testConfig(t,
		policy.Rule{
			Name:  "admin-denied",
			Match: policy.Match{PathPrefixes: []string{"/v1/admin"}},
		},
		policy.Rule{
			Name:  "everything-else",
			Match: policy.Match{PathPrefixes: []string{"/v1/"}},
			Allow: &policy.Allow{Public: true},
		},
	)

	rule, ok := config.Match(policy.Request{Method: "GET", Path: "/v1/admin/users"}, "/v1/admin/users")
	if !ok || rule.Name != "admin-denied" {
		t.Fatalf("first matching rule should win, got %v %v", rule, ok)
	}
	if rule.Allow != nil {
		t.Error("a rule with no allow block denies what it matches")
	}
}

func TestMatchRequiresEveryStatedField(t *testing.T) {
	config := testConfig(t, policy.Rule{
		Name: "api",
		Match: policy.Match{
			Hosts:        []string{"api.example.com", "*.internal.example.com"},
			Methods:      []string{"GET", "HEAD"},
			PathPrefixes: []string{"/v1/"},
		},
		Allow: &policy.Allow{Public: true},
	})

	tests := []struct {
		name  string
		req   policy.Request
		match bool
	}{
		{"exact host", policy.Request{Host: "api.example.com", Method: "GET", Path: "/v1/x"}, true},
		{"host with port", policy.Request{Host: "api.example.com:8443", Method: "GET", Path: "/v1/x"}, true},
		{"host case", policy.Request{Host: "API.example.com", Method: "GET", Path: "/v1/x"}, true},
		{"wildcard host", policy.Request{Host: "a.internal.example.com", Method: "GET", Path: "/v1/x"}, true},
		{"wildcard does not match the bare suffix", policy.Request{Host: "internal.example.com", Method: "GET", Path: "/v1/x"}, false},
		{"wrong host", policy.Request{Host: "evil.com", Method: "GET", Path: "/v1/x"}, false},
		{"wrong method", policy.Request{Host: "api.example.com", Method: "POST", Path: "/v1/x"}, false},
		{"wrong path", policy.Request{Host: "api.example.com", Method: "GET", Path: "/v2/x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := config.Match(tc.req, tc.req.Path)
			if ok != tc.match {
				t.Errorf("matched = %v, want %v", ok, tc.match)
			}
		})
	}
}

func TestValidateRejectsUnsafeConfigurations(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no rules denies everything",
			yaml: "rules: []",
			want: "no rules",
		},
		{
			// Accepting HS256 next to RS256 is how a token signed with the
			// public key gets in.
			name: "symmetric algorithm",
			yaml: `
issuers:
  - name: corp
    issuer: https://a/
    jwksURL: https://a/jwks
    audiences: [api]
    algorithms: [HS256]
rules:
  - name: r
    allow: {public: true}
`,
			want: `algorithm "HS256" is not supported`,
		},
		{
			name: "missing audience",
			yaml: `
issuers:
  - name: corp
    issuer: https://a/
    jwksURL: https://a/jwks
    algorithms: [RS256]
rules:
  - name: r
    allow: {public: true}
`,
			want: "audiences is required",
		},
		{
			name: "rule points at an issuer that does not exist",
			yaml: `
rules:
  - name: r
    allow: {issuers: [nope]}
`,
			want: `unknown issuer "nope"`,
		},
		{
			name: "public combined with scopes is ambiguous",
			yaml: `
rules:
  - name: r
    allow: {public: true, scopes: [admin]}
`,
			want: "cannot be combined",
		},
		{
			name: "unknown field is a typo, not a comment",
			yaml: `
rules:
  - name: r
    allow: {public: true}
    tenents: [acme]
`,
			want: "unknown field",
		},
		{
			name: "lower case method never matches",
			yaml: `
rules:
  - name: r
    match: {methods: [get]}
    allow: {public: true}
`,
			want: "must be upper case",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("expected the policy to be rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	config, err := policy.Parse([]byte("rules:\n  - name: r\n    allow: {public: true}\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if config.FailureMode != policy.FailClosed {
		t.Errorf("FailureMode = %q, want %q; a gateway that defaults to open is a gateway with a hole",
			config.FailureMode, policy.FailClosed)
	}
	if config.ForwardPrefix != policy.DefaultForwardPrefix {
		t.Errorf("ForwardPrefix = %q, want %q", config.ForwardPrefix, policy.DefaultForwardPrefix)
	}
}

// A broken edit must not take the policy down with it. Dropping to an empty
// policy on a YAML typo turns a mistake into a total outage.
func TestReloadKeepsTheLastGoodPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	good := "rules:\n  - name: first\n    allow: {public: true}\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := policy.NewStore(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := os.WriteFile(path, []byte("rules: [ this is not: valid"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("expected the broken policy to be rejected")
	}

	if got := store.Config().Rules[0].Name; got != "first" {
		t.Errorf("rule = %q, want the previous policy to still be in force", got)
	}
	if store.Failures() != 1 {
		t.Errorf("Failures() = %d, want 1", store.Failures())
	}

	updated := "rules:\n  - name: second\n    allow: {public: true}\n"
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := store.Config().Rules[0].Name; got != "second" {
		t.Errorf("rule = %q, want %q", got, "second")
	}
}
