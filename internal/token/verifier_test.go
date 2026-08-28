package token_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/JackFurton/portcullis/internal/policy"
	"github.com/JackFurton/portcullis/internal/testjwt"
	"github.com/JackFurton/portcullis/internal/token"
)

func newVerifier(t *testing.T) (*token.Verifier, *testjwt.Issuer, *policy.Issuer) {
	t.Helper()

	issuer := testjwt.New(t, "corp", "https://accounts.example.com/")
	config := issuer.Config()
	cache := token.NewKeyCache(&http.Client{Timeout: 2 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return token.NewVerifier(cache, token.DefaultCacheSize), issuer, &config
}

func TestVerifyAcceptsAValidToken(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	raw := issuer.Sign(t, testjwt.Claims{
		"sub":       "svc-billing",
		"tenant_id": "acme",
		"scope":     "events.read events.write",
	})

	identity, err := verifier.Verify(context.Background(), config, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if identity.Subject != "svc-billing" {
		t.Errorf("Subject = %q, want %q", identity.Subject, "svc-billing")
	}
	if identity.Tenant != "acme" {
		t.Errorf("Tenant = %q, want %q", identity.Tenant, "acme")
	}
	if !identity.HasScopes([]string{"events.read", "events.write"}) {
		t.Errorf("Scopes = %v, want both scopes", identity.Scopes)
	}
	if identity.HasScopes([]string{"admin"}) {
		t.Error("a scope the token does not carry must not be reported as present")
	}
}

// The header says HS256 and the MAC key is the issuer's public key, which
// anyone can fetch. A verifier that takes its algorithm from the token accepts
// this and hands out any identity the attacker asks for.
func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	raw := issuer.SignHS256WithPublicKey(t, testjwt.Claims{"sub": "attacker", "tenant_id": "victim"})

	_, err := verifier.Verify(context.Background(), config, raw)
	if err == nil {
		t.Fatal("a token signed with the public key as an HMAC secret must be rejected")
	}
	if !errors.Is(err, token.ErrMalformed) {
		t.Errorf("want the algorithm allowlist to reject it at parse time, got %v", err)
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	raw := issuer.SignNone(t, testjwt.Claims{"sub": "attacker"})

	if _, err := verifier.Verify(context.Background(), config, raw); err == nil {
		t.Fatal("an unsigned token must be rejected")
	}
}

func TestVerifyChecksTimeClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims testjwt.Claims
		want   error
	}{
		{
			name:   "expired",
			claims: testjwt.Claims{"exp": time.Now().Add(-time.Hour).Unix()},
			want:   token.ErrExpired,
		},
		{
			name:   "not yet valid",
			claims: testjwt.Claims{"nbf": time.Now().Add(time.Hour).Unix()},
			want:   token.ErrNotYetValid,
		},
		{
			// A token with no expiry can never be revoked by waiting, which
			// makes it a credential with no lifetime.
			name:   "no expiry",
			claims: testjwt.Claims{"exp": nil},
			want:   token.ErrMissingExpiry,
		},
		{
			name:   "issued in the future",
			claims: testjwt.Claims{"iat": time.Now().Add(time.Hour).Unix()},
			want:   token.ErrNotYetValid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifier, issuer, config := newVerifier(t)
			raw := issuer.Sign(t, tc.claims)

			_, err := verifier.Verify(context.Background(), config, raw)
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify() error = %v, want %v", err, tc.want)
			}
		})
	}
}

// Clock skew has to cut both ways, or a token minted by a server a few seconds
// ahead is rejected for the first few seconds of its life.
func TestVerifyToleratesClockSkew(t *testing.T) {
	verifier, issuer, config := newVerifier(t)
	config.ClockSkew = policy.Duration(30 * time.Second)

	raw := issuer.Sign(t, testjwt.Claims{
		"nbf": time.Now().Add(10 * time.Second).Unix(),
		"exp": time.Now().Add(-10 * time.Second).Unix(),
	})

	if _, err := verifier.Verify(context.Background(), config, raw); err != nil {
		t.Errorf("a token inside the skew window must be accepted, got %v", err)
	}
}

func TestVerifyChecksIssuerAndAudience(t *testing.T) {
	t.Run("wrong audience", func(t *testing.T) {
		verifier, issuer, config := newVerifier(t)
		raw := issuer.Sign(t, testjwt.Claims{"aud": "api://somewhere-else"})

		if _, err := verifier.Verify(context.Background(), config, raw); !errors.Is(err, token.ErrWrongAudience) {
			t.Errorf("error = %v, want %v", err, token.ErrWrongAudience)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		verifier, issuer, config := newVerifier(t)
		raw := issuer.Sign(t, testjwt.Claims{"iss": "https://evil.example.com/"})

		// The signature is fine: this is the issuer's own key. Only the claim
		// check stops a token minted for one tenant's realm from being replayed
		// at another.
		if _, err := verifier.Verify(context.Background(), config, raw); !errors.Is(err, token.ErrWrongIssuer) {
			t.Errorf("error = %v, want %v", err, token.ErrWrongIssuer)
		}
	})

	t.Run("audience array", func(t *testing.T) {
		verifier, issuer, config := newVerifier(t)
		raw := issuer.Sign(t, testjwt.Claims{"aud": []string{"api://other", issuer.Audience}})

		if _, err := verifier.Verify(context.Background(), config, raw); err != nil {
			t.Errorf("an aud array containing the expected value must be accepted, got %v", err)
		}
	})
}

func TestVerifyRejectsAForeignSignature(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	// A second issuer signing a token that claims to be the first one.
	other := testjwt.New(t, "evil", issuer.URL)
	raw := other.Sign(t, testjwt.Claims{"aud": issuer.Audience, "sub": "attacker"})

	if _, err := verifier.Verify(context.Background(), config, raw); err == nil {
		t.Fatal("a token signed by a key the issuer never published must be rejected")
	}
}

// A rotated key should start working without a restart, and the refetch it
// triggers must not happen once per request.
func TestVerifyRefetchesAfterKeyRotation(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	first := issuer.Sign(t, testjwt.Claims{})
	if _, err := verifier.Verify(context.Background(), config, first); err != nil {
		t.Fatalf("first token: %v", err)
	}
	fetches := issuer.Requests()

	issuer.Rotate(t)
	rotated := issuer.Sign(t, testjwt.Claims{})

	if _, err := verifier.Verify(context.Background(), config, rotated); err != nil {
		t.Fatalf("a token signed with the rotated key should verify after a refetch: %v", err)
	}
	if issuer.Requests() != fetches+1 {
		t.Errorf("expected exactly one refetch, saw %d", issuer.Requests()-fetches)
	}
}

// An unknown kid must not turn into one JWKS fetch per request, or a stream of
// forged tokens becomes a denial of service against the identity provider with
// this gateway as the amplifier.
func TestVerifyRateLimitsRefetchOnUnknownKey(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	if _, err := verifier.Verify(context.Background(), config, issuer.Sign(t, testjwt.Claims{})); err != nil {
		t.Fatalf("warm up: %v", err)
	}
	fetches := issuer.Requests()

	forged := testjwt.New(t, "forged", issuer.URL)
	for range 20 {
		raw := forged.Sign(t, testjwt.Claims{"aud": issuer.Audience})
		if _, err := verifier.Verify(context.Background(), config, raw); err == nil {
			t.Fatal("a token signed by an unknown key must be rejected")
		}
	}

	if extra := issuer.Requests() - fetches; extra > 1 {
		t.Errorf("20 forged tokens caused %d JWKS fetches, want at most 1", extra)
	}
}

// Claims end up in headers for the upstream, so a newline in one is a header
// injection into whatever is downstream.
func TestVerifyRejectsControlCharactersInClaims(t *testing.T) {
	verifier, issuer, config := newVerifier(t)

	raw := issuer.Sign(t, testjwt.Claims{"tenant_id": "acme\r\nx-admin: true"})

	if _, err := verifier.Verify(context.Background(), config, raw); !errors.Is(err, token.ErrUnsafeClaim) {
		t.Errorf("error = %v, want %v", err, token.ErrUnsafeClaim)
	}
}

func TestVerifyReadsScopesInBothShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"space delimited string", "events.read admin"},
		{"array", []string{"events.read", "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, issuer, config := newVerifier(t)
			raw := issuer.Sign(t, testjwt.Claims{"scope": tc.value})

			identity, err := verifier.Verify(context.Background(), config, raw)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !identity.HasScopes([]string{"events.read", "admin"}) {
				t.Errorf("Scopes = %v, want both", identity.Scopes)
			}
		})
	}
}

func TestVerifyRequiresASubject(t *testing.T) {
	verifier, issuer, config := newVerifier(t)
	raw := issuer.Sign(t, testjwt.Claims{"sub": nil})

	if _, err := verifier.Verify(context.Background(), config, raw); !errors.Is(err, token.ErrMissingSubject) {
		t.Errorf("error = %v, want %v", err, token.ErrMissingSubject)
	}
}

// Signature verification is the expensive part of a decision and a caller
// reuses one token for its whole lifetime, so the second check of the same
// token must not redo the work.
func TestVerifyCachesASuccessfulResult(t *testing.T) {
	verifier, issuer, config := newVerifier(t)
	raw := issuer.Sign(t, testjwt.Claims{"sub": "svc", "tenant_id": "acme"})

	first, err := verifier.Verify(context.Background(), config, raw)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	second, err := verifier.Verify(context.Background(), config, raw)
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}

	if first != second {
		t.Error("the second verification should have come from the cache")
	}
	if verifier.Cached() != 1 {
		t.Errorf("Cached() = %d, want 1", verifier.Cached())
	}

	verifier.Flush()
	if verifier.Cached() != 0 {
		t.Errorf("Cached() = %d after Flush, want 0", verifier.Cached())
	}
}

// A rejection is never cached: a token that failed while the issuer's keys
// were briefly unreachable has to be able to succeed once they come back.
func TestVerifyDoesNotCacheFailures(t *testing.T) {
	verifier, issuer, config := newVerifier(t)
	raw := issuer.Sign(t, testjwt.Claims{"exp": time.Now().Add(-time.Hour).Unix()})

	if _, err := verifier.Verify(context.Background(), config, raw); err == nil {
		t.Fatal("expected the expired token to be rejected")
	}
	if verifier.Cached() != 0 {
		t.Errorf("Cached() = %d, want failures not to be cached", verifier.Cached())
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer  abc ", "abc", true},
		{"Basic abc", "", false},
		{"abc", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := token.BearerToken(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BearerToken(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}
