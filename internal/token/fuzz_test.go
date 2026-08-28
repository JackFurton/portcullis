package token_test

import (
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/JackFurton/portcullis/internal/token"
)

// PeekIssuer reads a claim out of an unverified token, which makes it the one
// place in this service that touches attacker controlled data before any
// signature has been checked. It has to be impossible to make it do anything
// except return a string or say no.
func FuzzPeekIssuer(f *testing.F) {
	seeds := []string{
		"",
		"a.b.c",
		"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2EvIn0.sig",
		"eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2EvIn0.",
		"....",
		"...",
		strings.Repeat("a", 100) + "." + strings.Repeat("b", 100) + ".c",
		"eyJ9.eyJ9.eyJ9",
		"\x00.\x00.\x00",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		issuer, ok := token.PeekIssuer(raw)

		if !ok {
			if issuer != "" {
				t.Fatalf("PeekIssuer(%q) reported failure but returned %q", raw, issuer)
			}
			return
		}
		if issuer == "" {
			t.Fatalf("PeekIssuer(%q) reported success with an empty issuer", raw)
		}

		// The value is used to pick which configured issuer to verify
		// against, and is compared for equality against a configured string.
		// Anything that would be looked up has to be plain text, or a
		// configured issuer URL could be matched by something that is not one.
		for _, r := range issuer {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("PeekIssuer(%q) returned %q, which contains a control character", raw, issuer)
			}
		}
	})
}

// BearerToken splits a header value from the client. Getting it wrong in the
// permissive direction means accepting a credential in a form the rest of the
// stack does not expect.
func FuzzBearerToken(f *testing.F) {
	seeds := []string{
		"Bearer abc",
		"bearer abc",
		"BEARER  abc  ",
		"Bearer",
		"Bearer ",
		"Basic abc",
		"Bearer abc def",
		"",
		" ",
		"\tBearer\tabc",
		"Bearer\x00abc",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		credential, ok := token.BearerToken(header)

		if !ok {
			if credential != "" {
				t.Fatalf("BearerToken(%q) reported failure but returned %q", header, credential)
			}
			return
		}
		if credential == "" {
			t.Fatalf("BearerToken(%q) reported success with an empty credential", header)
		}
		if strings.TrimSpace(credential) != credential {
			t.Fatalf("BearerToken(%q) returned %q, which is not trimmed", header, credential)
		}
	})
}

// ParseSigned is the library call every token goes through. This target exists
// less to test go-jose than to pin the boundary: whatever it does with hostile
// input, this service must not panic on the way in or out of it.
func FuzzParseSigned(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhIn0.c2ln")
	f.Add("...")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16<<10 {
			t.Skip()
		}
		parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
		if err != nil {
			return
		}
		// A parsed object with no signature would mean an unsigned token got
		// this far, which the algorithm allowlist is supposed to prevent.
		if len(parsed.Signatures) == 0 {
			t.Fatalf("ParseSigned(%q) succeeded with no signatures", raw)
		}
	})
}
