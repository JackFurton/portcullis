package authz_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/JackFurton/portcullis/internal/authz"
	"github.com/JackFurton/portcullis/internal/policy"
	"github.com/JackFurton/portcullis/internal/testjwt"
	"github.com/JackFurton/portcullis/internal/token"
)

const policyTemplate = `
failureMode: deny
issuers:
  - name: corp
    issuer: %s
    jwksURL: %s
    audiences: [api://test]
    algorithms: [RS256]
    tenantClaim: tenant_id
    scopeClaim: scope
    forwardClaims: [email]
  - name: partner
    issuer: https://partner.example.com/
    jwksURL: https://partner.example.com/jwks
    audiences: [api://test]
    algorithms: [RS256]
rules:
  - name: health
    match:
      pathsExact: [/healthz]
      methods: [GET]
    allow:
      public: true

  - name: admin
    match:
      pathPrefixes: [/v1/admin]
    allow:
      issuers: [corp]
      scopes: [admin]
      tenants: [acme]

  - name: events-read
    match:
      pathPrefixes: [/v1/events]
      methods: [GET]
    allow:
      issuers: [corp]
      scopes: [events.read]
      tenants: ["*"]

  - name: internal-only
    match:
      pathPrefixes: [/v1/internal]
    allow:
      issuers: [partner]
`

type fixture struct {
	server *authz.Server
	issuer *testjwt.Issuer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	issuer := testjwt.New(t, "corp", "https://accounts.example.com/")

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := fmt.Sprintf(policyTemplate, issuer.URL, issuer.JWKSURL())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := policy.NewStore(path, log)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	keys := token.NewKeyCache(&http.Client{Timeout: 2 * time.Second}, log)

	return &fixture{
		server: authz.NewServer(store, token.NewVerifier(keys), log),
		issuer: issuer,
	}
}

func (f *fixture) check(t *testing.T, method, path string, headers map[string]string) *authv3.CheckResponse {
	t.Helper()

	if headers == nil {
		headers = map[string]string{}
	}
	resp, err := f.server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Host:    "api.example.com",
					Path:    path,
					Headers: headers,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check returned a gRPC error, which loses the decision: %v", err)
	}
	return resp
}

func (f *fixture) bearer(t *testing.T, claims testjwt.Claims) map[string]string {
	t.Helper()
	return map[string]string{"authorization": "Bearer " + f.issuer.Sign(t, claims)}
}

func allowed(resp *authv3.CheckResponse) bool {
	return resp.GetStatus().GetCode() == int32(codes.OK)
}

func deniedStatus(resp *authv3.CheckResponse) int {
	return int(resp.GetDeniedResponse().GetStatus().GetCode())
}

func deniedError(t *testing.T, resp *authv3.CheckResponse) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal([]byte(resp.GetDeniedResponse().GetBody()), &body); err != nil {
		t.Fatalf("deny body is not JSON: %v", err)
	}
	return body["error"]
}

func responseHeader(resp *authv3.CheckResponse, name string) string {
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == name {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

func deniedHeader(resp *authv3.CheckResponse, name string) string {
	for _, h := range resp.GetDeniedResponse().GetHeaders() {
		if h.GetHeader().GetKey() == name {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

func TestPublicRuleNeedsNoToken(t *testing.T) {
	f := newFixture(t)

	resp := f.check(t, "GET", "/healthz", nil)
	if !allowed(resp) {
		t.Fatalf("health check should be allowed, got %d", deniedStatus(resp))
	}
}

func TestProtectedRuleRequiresAToken(t *testing.T) {
	f := newFixture(t)

	resp := f.check(t, "GET", "/v1/events", nil)
	if allowed(resp) {
		t.Fatal("a protected route must not be reachable without a token")
	}
	if got := deniedStatus(resp); got != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := deniedHeader(resp, "www-authenticate"); got == "" {
		t.Error("a 401 must carry a WWW-Authenticate challenge")
	}
}

func TestValidTokenIsAllowedAndIdentityIsForwarded(t *testing.T) {
	f := newFixture(t)

	headers := f.bearer(t, testjwt.Claims{
		"sub":       "svc-reporting",
		"tenant_id": "globex",
		"scope":     "events.read",
		"email":     "svc@example.com",
	})

	resp := f.check(t, "GET", "/v1/events/123", headers)
	if !allowed(resp) {
		t.Fatalf("expected allow, got %d %s", deniedStatus(resp), deniedError(t, resp))
	}

	for name, want := range map[string]string{
		"x-portcullis-subject":     "svc-reporting",
		"x-portcullis-tenant":      "globex",
		"x-portcullis-issuer":      "corp",
		"x-portcullis-scopes":      "events.read",
		"x-portcullis-claim-email": "svc@example.com",
	} {
		if got := responseHeader(resp, name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}

	metadata := resp.GetDynamicMetadata().AsMap()
	if metadata["tenant"] != "globex" || metadata["rule"] != "events-read" {
		t.Errorf("dynamic metadata = %v, want the tenant and rule recorded", metadata)
	}
}

// The upstream trusts these headers, so a caller must never be able to set
// them. Removing the whole namespace matters more than overwriting the ones
// this service happens to populate.
func TestForwardedHeadersCannotBeSpoofed(t *testing.T) {
	t.Run("on a public rule with no token", func(t *testing.T) {
		f := newFixture(t)

		resp := f.check(t, "GET", "/healthz", map[string]string{
			"x-portcullis-tenant":  "acme",
			"x-portcullis-subject": "root",
		})
		if !allowed(resp) {
			t.Fatal("expected allow")
		}

		removed := resp.GetOkResponse().GetHeadersToRemove()
		for _, name := range []string{"x-portcullis-tenant", "x-portcullis-subject"} {
			if !slices.Contains(removed, name) {
				t.Errorf("%s reaches the upstream unmodified; removed = %v", name, removed)
			}
		}
	})

	t.Run("alongside a valid token", func(t *testing.T) {
		f := newFixture(t)

		headers := f.bearer(t, testjwt.Claims{"tenant_id": "globex", "scope": "events.read"})
		headers["x-portcullis-tenant"] = "acme"

		resp := f.check(t, "GET", "/v1/events", headers)
		if !allowed(resp) {
			t.Fatalf("expected allow, got %d", deniedStatus(resp))
		}
		if got := responseHeader(resp, "x-portcullis-tenant"); got != "globex" {
			t.Errorf("tenant header = %q, want the value from the token", got)
		}
		// Envoy applies headers_to_remove after the headers it adds, so a
		// header that is both set and listed for removal reaches the upstream
		// missing entirely. Overwriting is what replaces the spoofed value.
		if slices.Contains(resp.GetOkResponse().GetHeadersToRemove(), "x-portcullis-tenant") {
			t.Error("a header this decision sets must not also be listed for removal, or the value is deleted")
		}
	})
}

func TestDenials(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		claims     testjwt.Claims
		noToken    bool
		wantStatus int
		wantError  string
	}{
		{
			name:       "missing scope",
			method:     "GET",
			path:       "/v1/events",
			claims:     testjwt.Claims{"tenant_id": "acme", "scope": "events.write"},
			wantStatus: http.StatusForbidden,
			wantError:  "insufficient_scope",
		},
		{
			name:       "wrong tenant",
			method:     "GET",
			path:       "/v1/admin/users",
			claims:     testjwt.Claims{"tenant_id": "globex", "scope": "admin"},
			wantStatus: http.StatusForbidden,
			wantError:  "wrong_tenant",
		},
		{
			// The rule asks for any tenant, so a token with none does not pass.
			name:       "no tenant where one is required",
			method:     "GET",
			path:       "/v1/events",
			claims:     testjwt.Claims{"scope": "events.read"},
			wantStatus: http.StatusForbidden,
			wantError:  "wrong_tenant",
		},
		{
			name:       "issuer not accepted by this rule",
			method:     "GET",
			path:       "/v1/internal/metrics",
			claims:     testjwt.Claims{"tenant_id": "acme"},
			wantStatus: http.StatusForbidden,
			wantError:  "issuer_not_allowed",
		},
		{
			name:       "expired token",
			method:     "GET",
			path:       "/v1/events",
			claims:     testjwt.Claims{"tenant_id": "acme", "scope": "events.read", "exp": time.Now().Add(-time.Hour).Unix()},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
		},
		{
			name:       "no rule matches",
			method:     "GET",
			path:       "/v2/anything",
			noToken:    true,
			wantStatus: http.StatusForbidden,
			wantError:  "no_matching_rule",
		},
		{
			// Traversal that would reach the admin prefix if the path were
			// decoded after matching instead of before.
			name:       "encoded traversal",
			method:     "GET",
			path:       "/v1/events/%2e%2e/admin",
			noToken:    true,
			wantStatus: http.StatusBadRequest,
			wantError:  "malformed_path",
		},
		{
			name:       "method not covered by the rule",
			method:     "DELETE",
			path:       "/v1/events/1",
			noToken:    true,
			wantStatus: http.StatusForbidden,
			wantError:  "no_matching_rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)

			var headers map[string]string
			if !tc.noToken {
				headers = f.bearer(t, tc.claims)
			}

			resp := f.check(t, tc.method, tc.path, headers)
			if allowed(resp) {
				t.Fatal("expected a denial")
			}
			if got := deniedStatus(resp); got != tc.wantStatus {
				t.Errorf("status = %d, want %d", got, tc.wantStatus)
			}
			if got := deniedError(t, resp); got != tc.wantError {
				t.Errorf("error = %q, want %q", got, tc.wantError)
			}
		})
	}
}

// An open endpoint must not become a way to find out whether a forged token
// would be accepted somewhere else.
func TestPublicRuleIgnoresAnInvalidToken(t *testing.T) {
	f := newFixture(t)

	forged := testjwt.New(t, "forged", f.issuer.URL)
	headers := map[string]string{"authorization": "Bearer " + forged.Sign(t, testjwt.Claims{"aud": "api://test"})}

	resp := f.check(t, "GET", "/healthz", headers)
	if !allowed(resp) {
		t.Fatalf("a public route must stay public, got %d %s", deniedStatus(resp), deniedError(t, resp))
	}
	if got := responseHeader(resp, "x-portcullis-subject"); got != "" {
		t.Errorf("an unverified token must not produce an identity, got subject %q", got)
	}
}

// A valid token on a public route still identifies the caller, which is what
// makes optional authentication useful.
func TestPublicRuleForwardsAValidIdentity(t *testing.T) {
	f := newFixture(t)

	headers := f.bearer(t, testjwt.Claims{"sub": "known-caller", "tenant_id": "acme"})

	resp := f.check(t, "GET", "/healthz", headers)
	if !allowed(resp) {
		t.Fatalf("expected allow, got %d", deniedStatus(resp))
	}
	if got := responseHeader(resp, "x-portcullis-subject"); got != "known-caller" {
		t.Errorf("subject header = %q, want the identity forwarded", got)
	}
}

// A route that establishes no identity must still strip the namespace, and a
// route that establishes one must strip whatever it did not set.
func TestUnsetForwardedHeadersAreStripped(t *testing.T) {
	f := newFixture(t)

	headers := f.bearer(t, testjwt.Claims{"sub": "caller", "tenant_id": "globex", "scope": "events.read"})
	headers["x-portcullis-claim-role"] = "admin"

	resp := f.check(t, "GET", "/v1/events", headers)
	if !allowed(resp) {
		t.Fatalf("expected allow, got %d", deniedStatus(resp))
	}
	if !slices.Contains(resp.GetOkResponse().GetHeadersToRemove(), "x-portcullis-claim-role") {
		t.Error("a forwarded header this decision did not set must be stripped")
	}
}

// Envoy turns a gRPC error into a decision this service did not make. Every
// path has to answer with an explicit allow or deny instead.
func TestMalformedCheckRequestFailsClosedWithoutAGRPCError(t *testing.T) {
	f := newFixture(t)

	resp, err := f.server.Check(context.Background(), &authv3.CheckRequest{})
	if err != nil {
		t.Fatalf("Check should not return a gRPC error: %v", err)
	}
	if allowed(resp) {
		t.Fatal("a request with no attributes must not be allowed under the default failure mode")
	}
	if got := deniedStatus(resp); got != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", got, http.StatusServiceUnavailable)
	}
}
