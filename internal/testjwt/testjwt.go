// Package testjwt mints real tokens against a real key set for tests.
//
// The tests verify signatures rather than stubbing verification, because the
// bugs worth catching in this service live in exactly the code a stub would
// replace: which algorithms are accepted, which key is selected, and which
// claims are checked.
package testjwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/JackFurton/portcullis/internal/policy"
)

// Issuer is a fake identity provider: an RSA key, a JWKS endpoint serving it,
// and a way to sign tokens.
type Issuer struct {
	Name      string
	URL       string
	Audience  string
	KeyID     string
	Requests  func() int
	key       *rsa.PrivateKey
	server    *httptest.Server
	rotations int
}

// New starts an issuer with one signing key.
func New(t *testing.T, name, url string) *Issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	issuer := &Issuer{
		Name:     name,
		URL:      url,
		Audience: "api://test",
		KeyID:    "key-1",
		key:      key,
	}

	var requests int
	issuer.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(issuer.keySet()); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}))
	issuer.Requests = func() int { return requests }
	t.Cleanup(issuer.server.Close)

	return issuer
}

// JWKSURL is where the key set is published.
func (i *Issuer) JWKSURL() string { return i.server.URL }

// Config returns the policy stanza describing this issuer.
func (i *Issuer) Config() policy.Issuer {
	return policy.Issuer{
		Name:        i.Name,
		Issuer:      i.URL,
		JWKSURL:     i.JWKSURL(),
		Audiences:   []string{i.Audience},
		Algorithms:  []string{"RS256"},
		TenantClaim: "tenant_id",
		ScopeClaim:  "scope",
	}
}

// Rotate replaces the signing key and publishes the new one, the way an
// issuer does when it rolls a key.
func (i *Issuer) Rotate(t *testing.T) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	i.rotations++
	i.key = key
	i.KeyID = "key-" + string(rune('1'+i.rotations))
}

func (i *Issuer) keySet() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       i.key.Public(),
		KeyID:     i.KeyID,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
}

// Claims are the token contents, with sensible defaults filled in by Sign.
type Claims map[string]any

// Sign mints a valid RS256 token. Any claim left out gets a default that makes
// the token valid, so a test only states the thing it is testing.
func (i *Issuer) Sign(t *testing.T, claims Claims) string {
	t.Helper()

	payload := Claims{
		"iss": i.URL,
		"sub": "user-1",
		"aud": i.Audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for name, value := range claims {
		if value == nil {
			delete(payload, name)
			continue
		}
		payload[name] = value
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.KeyID),
	)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	object, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized
}

// SignHS256WithPublicKey forges the classic algorithm confusion token: the
// header says HS256, and the MAC key is the issuer's public key, which is
// public. Any verifier that picks its algorithm from the token header rather
// than from configuration accepts this.
func (i *Issuer) SignHS256WithPublicKey(t *testing.T, claims Claims) string {
	t.Helper()

	public, err := json.Marshal(jose.JSONWebKey{Key: i.key.Public(), KeyID: i.KeyID, Algorithm: "RS256"})
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return forge(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": i.KeyID}, i.fill(claims), func(signing []byte) []byte {
		mac := hmac.New(sha256.New, public)
		mac.Write(signing)
		return mac.Sum(nil)
	})
}

// SignNone mints a token with no signature at all.
func (i *Issuer) SignNone(t *testing.T, claims Claims) string {
	t.Helper()
	return forge(t, map[string]any{"alg": "none", "typ": "JWT"}, i.fill(claims), func([]byte) []byte { return nil })
}

func (i *Issuer) fill(claims Claims) Claims {
	payload := Claims{
		"iss": i.URL,
		"sub": "user-1",
		"aud": i.Audience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range claims {
		payload[name] = value
	}
	return payload
}

func forge(t *testing.T, header map[string]any, claims Claims, sign func([]byte) []byte) string {
	t.Helper()

	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signing := encode(header) + "." + encode(claims)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(signing)))
}
