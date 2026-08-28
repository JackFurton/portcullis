// Command demoidp is a stand-in identity provider for the demo.
//
// It publishes a JWKS endpoint and mints tokens on request, so the whole
// authorization path can be exercised without an account anywhere. It is not
// an OAuth server: there is no client authentication, and anyone who can reach
// it can mint any token. That is the point for a demo and disqualifying for
// anything else, which is why it refuses to start without an explicit flag.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func main() {
	var (
		addr      = flag.String("addr", ":9000", "address to listen on")
		issuerURL = flag.String("issuer", "http://demoidp:9000/", "value of the iss claim")
		audience  = flag.String("audience", "api://demo", "value of the aud claim")
		unsafe    = flag.Bool("i-understand-this-mints-tokens-for-anyone", false, "required acknowledgement")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if !*unsafe {
		log.Error("refusing to start: this mints tokens for anyone who can reach it, " +
			"pass --i-understand-this-mints-tokens-for-anyone to run it anyway")
		os.Exit(1)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error("generate key", "error", err)
		os.Exit(1)
	}

	idp := &provider{key: key, keyID: "demo-1", issuer: *issuerURL, audience: *audience, log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", idp.jwks)
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	log.Info("demo identity provider listening", "addr", *addr, "issuer", *issuerURL)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

type provider struct {
	key      *rsa.PrivateKey
	keyID    string
	issuer   string
	audience string
	log      *slog.Logger
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       p.key.Public(),
		KeyID:     p.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		p.log.Error("encode JWKS", "error", err)
	}
}

// token mints a JWT from query parameters:
//
//	/token?sub=svc-a&tenant=acme&scope=events.read+admin&ttl=5m
//
// Pass ttl=-1m to mint one that is already expired, which is the quickest way
// to see a 401 with a real token rather than a missing one.
func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	ttl := 15 * time.Minute
	if raw := query.Get("ttl"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			http.Error(w, "bad ttl: "+err.Error(), http.StatusBadRequest)
			return
		}
		ttl = parsed
	}

	audience := p.audience
	if raw := query.Get("aud"); raw != "" {
		audience = raw
	}
	issuer := p.issuer
	if raw := query.Get("iss"); raw != "" {
		issuer = raw
	}

	claims := map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": valueOr(query.Get("sub"), "demo-user"),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(ttl).Unix(),
	}
	if tenant := query.Get("tenant"); tenant != "" {
		claims["tenant_id"] = tenant
	}
	if scope := query.Get("scope"); scope != "" {
		claims["scope"] = strings.Join(strings.Fields(scope), " ")
	}
	if email := query.Get("email"); email != "" {
		claims["email"] = email
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	object, err := signer.Sign(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Plain text by default so the demo is one shell substitution.
	if query.Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": serialized,
			"token_type":   "Bearer",
			"expires_in":   strconv.Itoa(int(ttl.Seconds())),
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintln(w, serialized)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
