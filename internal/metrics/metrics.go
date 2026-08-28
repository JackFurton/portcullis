// Package metrics holds the Prometheus collectors this service exports.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Label values for the decision counter.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionError = "error"
)

var (
	// Decisions counts what this service decided and why.
	//
	// There is deliberately no tenant or subject label. Both are attacker
	// influenced and unbounded, and a label like that is how a metrics
	// endpoint becomes the thing that takes the cluster down. Rule names come
	// from the policy file, so they are bounded by definition.
	Decisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_decisions_total",
		Help: "Authorization decisions by outcome, reason and matched rule.",
	}, []string{"decision", "reason", "rule"})

	// CheckDuration measures how long a decision takes. This service is in the
	// request path of everything, so its own latency is everyone's latency.
	CheckDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portcullis_check_duration_seconds",
		Help:    "Time spent reaching an authorization decision.",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1},
	}, []string{"decision"})

	// PolicyReloads counts policy reload attempts. A rising failure count with
	// a flat success count means someone's edit is not taking effect.
	PolicyReloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_policy_reloads_total",
		Help: "Policy reload attempts by result.",
	}, []string{"result"})

	// JWKSFetches counts key set fetches per issuer.
	JWKSFetches = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_jwks_fetches_total",
		Help: "JWKS fetches by issuer and result.",
	}, []string{"issuer", "result"})
)
