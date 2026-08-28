// Package authz implements the Envoy external authorization service.
package authz

import (
	"fmt"
	"net/http"

	"github.com/JackFurton/portcullis/internal/token"
)

// Reason is a stable, low cardinality code for why a request was decided the
// way it was. It goes in metrics, in logs, and in the response body, so an
// operator reading a dashboard and a developer reading a 403 are looking at
// the same word.
type Reason string

// The reasons this service can give. Every denial maps to exactly one, so a
// spike on a dashboard names the check that is firing.
const (
	ReasonAllowed           Reason = "allowed"
	ReasonPublic            Reason = "allowed_public"
	ReasonNoRule            Reason = "no_matching_rule"
	ReasonRuleDenies        Reason = "rule_denies"
	ReasonMalformedPath     Reason = "malformed_path"
	ReasonMissingToken      Reason = "missing_token"
	ReasonUnknownIssuer     Reason = "unknown_issuer"
	ReasonIssuerNotAllowed  Reason = "issuer_not_allowed"
	ReasonInvalidToken      Reason = "invalid_token"
	ReasonInsufficientScope Reason = "insufficient_scope"
	ReasonWrongTenant       Reason = "wrong_tenant"
	ReasonWrongSubject      Reason = "wrong_subject"
	ReasonInternal          Reason = "internal_error"
)

// decision is the outcome of evaluating one request.
type decision struct {
	allowed bool
	reason  Reason
	rule    string
	// shadow is set when the policy would have denied this request but is
	// running in shadow mode, so it was allowed anyway. reason still holds the
	// reason it would have been denied, which is the whole point of recording
	// it.
	shadow bool
	status int
	// challenge is the WWW-Authenticate value, set on 401s.
	challenge string
	// identity is set when a valid token was presented, including on public
	// rules where no token was required.
	identity *token.Identity
	// detail is logged but never returned to the caller. A 401 that explains
	// exactly which check failed is a tool for guessing at the next one.
	detail string
}

// shadowed converts a denial into an allow that remembers what it would have
// done. The identity is carried through so the upstream sees the same headers
// it will see once the rule is enforced, which is what makes a shadow rollout
// tell you something.
func (d decision) shadowed() decision {
	d.allowed = true
	d.shadow = true
	d.status = 0
	d.challenge = ""
	return d
}

// withIdentity attaches the verified caller to a decision. Denials that happen
// after verification carry it too: it is what lets a shadowed rule forward the
// same headers it will forward once enforced, and it means an enforced denial
// can say who was refused rather than just that someone was.
func (d decision) withIdentity(identity *token.Identity) decision {
	d.identity = identity
	return d
}

func allow(rule string, reason Reason, identity *token.Identity) decision {
	return decision{allowed: true, reason: reason, rule: rule, identity: identity}
}

func deny(rule string, reason Reason, status int, detail string) decision {
	return decision{allowed: false, reason: reason, rule: rule, status: status, detail: detail}
}

// unauthorized is a 401 with the challenge RFC 6750 asks for. The error code
// in the challenge is part of the protocol, so it is specific even though the
// body is not.
func unauthorized(rule string, reason Reason, oauthError, detail string) decision {
	return decision{
		allowed:   false,
		reason:    reason,
		rule:      rule,
		status:    http.StatusUnauthorized,
		challenge: fmt.Sprintf(`Bearer error=%q`, oauthError),
		detail:    detail,
	}
}
