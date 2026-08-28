package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// PeekIssuer reads the iss claim out of a compact JWS without verifying
// anything.
//
// This value is untrusted and is used for exactly one thing: choosing which
// configured issuer to verify the token against. The verification that follows
// requires the iss claim to equal that issuer's configured value, so a token
// claiming an issuer it was not signed by fails there. Nothing else in this
// service may read a claim before the signature is checked.
func PeekIssuer(raw string) (string, bool) {
	if len(raw) > maxTokenBytes {
		return "", false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return claims.Issuer, claims.Issuer != ""
}

// BearerToken pulls the credential out of an Authorization header value. The
// scheme comparison is case insensitive because RFC 7235 says it is, and
// clients take that seriously in both directions.
func BearerToken(header string) (string, bool) {
	scheme, credential, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(scheme), "bearer") {
		return "", false
	}
	credential = strings.TrimSpace(credential)
	return credential, credential != ""
}
