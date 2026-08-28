package authz_test

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/JackFurton/portcullis/internal/testjwt"
)

// This service runs on every request through the mesh, so its own cost is
// everyone's cost. These benchmarks measure the whole Check call: matching the
// rule, verifying the signature, checking the claims, and building the
// response. Only the JWKS fetch is excluded, because it is cached and happens
// once per key rotation rather than once per request.

// BenchmarkCheckAllowed is the common case: a valid token on a protected route.
func BenchmarkCheckAllowed(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t)
	headers := map[string]string{
		"authorization": "Bearer " + f.issuer.Sign(t, testjwt.Claims{
			"sub":       "svc-reporting",
			"tenant_id": "acme",
			"scope":     "events.read",
		}),
		"x-request-id": "bench",
	}
	benchmarkCheckWith(b, f, "/v1/events", headers)
}

// BenchmarkCheckPublic is the cheapest path: a public rule and no token.
func BenchmarkCheckPublic(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t)
	benchmarkCheckWith(b, f, "/healthz", map[string]string{"x-request-id": "bench"})
}

// BenchmarkCheckDenied verifies the token and then refuses it, so it is the
// allowed path plus the denial response.
func BenchmarkCheckDenied(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t)
	headers := map[string]string{
		"authorization": "Bearer " + f.issuer.Sign(t, testjwt.Claims{
			"sub":       "svc-reporting",
			"tenant_id": "acme",
			"scope":     "events.write",
		}),
	}
	benchmarkCheckWith(b, f, "/v1/events", headers)
}

// BenchmarkCheckAllowedUncached is the cost with the cache disabled: every
// check pays for the full RSA verification. The gap between this and
// BenchmarkCheckAllowed is what the cache is worth.
func BenchmarkCheckAllowedUncached(b *testing.B) {
	t := &testing.T{}
	f := newFixtureWithCache(t, 0)
	headers := map[string]string{
		"authorization": "Bearer " + f.issuer.Sign(t, testjwt.Claims{
			"sub":       "svc-reporting",
			"tenant_id": "acme",
			"scope":     "events.read",
		}),
	}
	benchmarkCheckWith(b, f, "/v1/events", headers)
}

// BenchmarkCheckNoToken measures the path that never touches crypto.
func BenchmarkCheckNoToken(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t)
	benchmarkCheckWith(b, f, "/v1/events", map[string]string{})
}

func benchmarkCheckWith(b *testing.B, f *fixture, path string, headers map[string]string) {
	b.Helper()

	request := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Host:    "api.example.com",
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
	if _, err := f.server.Check(context.Background(), request); err != nil {
		b.Fatalf("warm up: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := f.server.Check(context.Background(), request); err != nil {
			b.Fatalf("Check: %v", err)
		}
	}
}
