package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/JackFurton/portcullis/internal/policy"
	"github.com/JackFurton/portcullis/internal/token"
)

// Evaluator turns a request into a decision. It is separate from the gRPC
// server so the policy logic can be tested without building protobufs.
type Evaluator struct {
	store    *policy.Store
	verifier *token.Verifier
	log      *slog.Logger
}

// NewEvaluator builds an Evaluator.
func NewEvaluator(store *policy.Store, verifier *token.Verifier, log *slog.Logger) *Evaluator {
	return &Evaluator{store: store, verifier: verifier, log: log}
}

// Evaluate decides one request. It never returns an error: every path ends in
// a decision, because a service that can fail to answer is a service that has
// to be given a default, and the default belongs in the policy.
func (e *Evaluator) Evaluate(ctx context.Context, req policy.Request, authorization string) decision {
	config := e.store.Config()

	d, rule := e.decide(ctx, config, req, authorization)

	// Shadow is applied last, to the finished decision, so every denial goes
	// through exactly one place on its way to being suppressed. An internal
	// error is left alone: failureMode governs that, and quietly allowing a
	// request the service could not evaluate is not what shadow means.
	if !d.allowed && d.reason != ReasonInternal && config.EffectiveMode(rule) == policy.ModeShadow {
		return d.shadowed()
	}
	return d
}

// decide works out what the policy says, ignoring mode. It returns the rule it
// matched so the caller can find the mode that applies.
func (e *Evaluator) decide(ctx context.Context, config *policy.Config, req policy.Request, authorization string) (decision, *policy.Rule) {
	path, err := policy.NormalizePath(req.Path)
	if err != nil {
		// The path this service matched on has to be the path the upstream
		// routes on. When it cannot be reduced to one, no rule means anything.
		return deny("", ReasonMalformedPath, http.StatusBadRequest, err.Error()), nil
	}

	rule, ok := config.Match(req, path)
	if !ok {
		return deny("", ReasonNoRule, http.StatusForbidden, "no rule matched"), nil
	}
	if rule.Allow == nil {
		return deny(rule.Name, ReasonRuleDenies, http.StatusForbidden, "rule has no allow block"), rule
	}

	raw, hasToken := token.BearerToken(authorization)

	if rule.Allow.Public {
		if !hasToken {
			return allow(rule.Name, ReasonPublic, nil), rule
		}
		// A public rule with a token attached still identifies the caller when
		// it can, but a token that does not verify is not a denial. Making it
		// one would turn every open endpoint into a way to test forged tokens.
		identity, err := e.verify(ctx, config, raw)
		if err != nil {
			e.log.Debug("ignoring an invalid token on a public rule", "rule", rule.Name, "error", err)
			return allow(rule.Name, ReasonPublic, nil), rule
		}
		return allow(rule.Name, ReasonPublic, identity), rule
	}

	if !hasToken {
		return unauthorized(rule.Name, ReasonMissingToken, "invalid_request", "no bearer token"), rule
	}

	issuerURL, ok := token.PeekIssuer(raw)
	if !ok {
		return unauthorized(rule.Name, ReasonInvalidToken, "invalid_token", "token has no readable issuer"), rule
	}
	issuer, ok := config.IssuerByURL(issuerURL)
	if !ok {
		return unauthorized(rule.Name, ReasonUnknownIssuer, "invalid_token",
			fmt.Sprintf("issuer %q is not configured", issuerURL)), rule
	}

	// Whether this rule accepts this issuer is checked before the signature.
	// It costs nothing and keeps an unrelated issuer's outage from turning
	// into failed verifications on rules that would have rejected it anyway.
	if len(rule.Allow.Issuers) > 0 && !slices.Contains(rule.Allow.Issuers, issuer.Name) {
		return deny(rule.Name, ReasonIssuerNotAllowed, http.StatusForbidden,
			fmt.Sprintf("rule does not accept issuer %q", issuer.Name)), rule
	}

	identity, err := e.verifier.Verify(ctx, issuer, raw)
	if err != nil {
		if isUpstreamFailure(err) {
			return e.failure(config, rule.Name, fmt.Sprintf("cannot verify against issuer %q: %v", issuer.Name, err)), rule
		}
		return unauthorized(rule.Name, ReasonInvalidToken, "invalid_token", err.Error()), rule
	}

	if len(rule.Allow.Tenants) > 0 {
		switch {
		case identity.Tenant == "":
			return deny(rule.Name, ReasonWrongTenant, http.StatusForbidden, "token carries no tenant").
				withIdentity(identity), rule
		case slices.Contains(rule.Allow.Tenants, policy.AnyTenant):
			// Any tenant will do, but there has to be one.
		case !slices.Contains(rule.Allow.Tenants, identity.Tenant):
			return deny(rule.Name, ReasonWrongTenant, http.StatusForbidden, "tenant is not allowed by this rule").
				withIdentity(identity), rule
		}
	}

	if len(rule.Allow.Subjects) > 0 && !slices.Contains(rule.Allow.Subjects, identity.Subject) {
		return deny(rule.Name, ReasonWrongSubject, http.StatusForbidden, "subject is not allowed by this rule").
			withIdentity(identity), rule
	}

	if !identity.HasScopes(rule.Allow.Scopes) {
		d := deny(rule.Name, ReasonInsufficientScope, http.StatusForbidden, "token is missing a required scope").
			withIdentity(identity)
		d.challenge = fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, strings.Join(rule.Allow.Scopes, " "))
		return d, rule
	}

	return allow(rule.Name, ReasonAllowed, identity), rule
}

// verify picks the issuer from the token and verifies against it. Used for the
// optional token on a public rule.
func (e *Evaluator) verify(ctx context.Context, config *policy.Config, raw string) (*token.Identity, error) {
	issuerURL, ok := token.PeekIssuer(raw)
	if !ok {
		return nil, errors.New("token has no readable issuer")
	}
	issuer, ok := config.IssuerByURL(issuerURL)
	if !ok {
		return nil, fmt.Errorf("issuer %q is not configured", issuerURL)
	}
	return e.verifier.Verify(ctx, issuer, raw)
}

// failure applies the configured failure mode. It is reached when the service
// could not reach a decision, which is different from deciding to deny.
func (e *Evaluator) failure(config *policy.Config, rule, detail string) decision {
	if config.FailureMode == policy.FailOpen {
		e.log.Error("failing open", "rule", rule, "detail", detail)
		d := allow(rule, ReasonInternal, nil)
		d.detail = detail
		return d
	}
	e.log.Error("failing closed", "rule", rule, "detail", detail)
	return deny(rule, ReasonInternal, http.StatusServiceUnavailable, detail)
}

// isUpstreamFailure separates "this token is bad" from "I could not find out".
// The first is a 401 the caller can act on; the second is this service's
// problem and follows the failure mode.
func isUpstreamFailure(err error) bool {
	if errors.Is(err, token.ErrUnknownKey) {
		// An unknown key is ambiguous: a rotated key set that has not been
		// refetched, or a token signed by nobody. It is treated as the
		// caller's problem, because the alternative fails a whole endpoint
		// open on one forged kid.
		return false
	}
	for _, sentinel := range []error{
		token.ErrMalformed, token.ErrBadSignature, token.ErrWrongIssuer, token.ErrWrongAudience,
		token.ErrExpired, token.ErrNotYetValid, token.ErrMissingExpiry, token.ErrUnsafeClaim,
		token.ErrMissingSubject,
	} {
		if errors.Is(err, sentinel) {
			return false
		}
	}
	return true
}
