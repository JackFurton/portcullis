package authz

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/JackFurton/portcullis/internal/metrics"
	"github.com/JackFurton/portcullis/internal/policy"
	"github.com/JackFurton/portcullis/internal/token"
)

// Server implements the Envoy external authorization gRPC service.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	evaluator *Evaluator
	store     *policy.Store
	log       *slog.Logger
}

// NewServer builds the gRPC service.
func NewServer(store *policy.Store, verifier *token.Verifier, log *slog.Logger) *Server {
	return &Server{
		evaluator: NewEvaluator(store, verifier, log),
		store:     store,
		log:       log,
	}
}

// Check answers one authorization request.
//
// It always returns a nil error. A gRPC error here is not a denial: depending
// on the filter's failure_mode_allow setting Envoy either fails the request
// with a 403 it generated itself, losing the reason, or lets it through. Both
// are worse than answering with an explicit decision this service chose.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()

	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		// Without request attributes there is nothing to authorize. This means
		// the filter is misconfigured, so it follows the failure mode.
		d := s.evaluator.failure(s.store.Config(), "", "check request carried no HTTP attributes")
		return s.respond(d, nil), nil
	}

	headers := httpReq.GetHeaders()
	request := policy.Request{
		Host:   httpReq.GetHost(),
		Method: httpReq.GetMethod(),
		Path:   httpReq.GetPath(),
	}

	d := s.evaluator.Evaluate(ctx, request, headers["authorization"])

	outcome := metrics.DecisionAllow
	switch {
	case d.reason == ReasonInternal:
		outcome = metrics.DecisionError
	case !d.allowed:
		outcome = metrics.DecisionDeny
	}
	metrics.Decisions.WithLabelValues(outcome, string(d.reason), d.rule).Inc()
	metrics.CheckDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())

	s.logDecision(d, request, headers)
	return s.respond(d, headers), nil
}

func (s *Server) logDecision(d decision, req policy.Request, headers map[string]string) {
	attrs := []any{
		"decision", map[bool]string{true: "allow", false: "deny"}[d.allowed],
		"reason", d.reason,
		"rule", d.rule,
		"method", req.Method,
		"host", req.Host,
		"path", req.Path,
		"requestID", headers["x-request-id"],
	}
	if d.identity != nil {
		attrs = append(attrs, "subject", d.identity.Subject, "tenant", d.identity.Tenant, "issuer", d.identity.IssuerName)
	}
	if d.detail != "" {
		// The detail is logged and never returned. A 401 that names the failed
		// check tells whoever is probing which one to work on next.
		attrs = append(attrs, "detail", d.detail)
	}
	if d.allowed {
		s.log.Debug("allowed", attrs...)
		return
	}
	s.log.Info("denied", attrs...)
}

func (s *Server) respond(d decision, headers map[string]string) *authv3.CheckResponse {
	if d.allowed {
		return s.okResponse(d, headers)
	}
	return s.deniedResponse(d)
}

func (s *Server) okResponse(d decision, headers map[string]string) *authv3.CheckResponse {
	prefix := s.store.Config().ForwardPrefix

	response := &authv3.OkHttpResponse{}
	set := map[string]bool{}

	if identity := d.identity; identity != nil {
		add := func(name, value string) {
			response.Headers = append(response.Headers, header(name, value))
			set[name] = true
		}
		add(prefix+"subject", identity.Subject)
		add(prefix+"issuer", identity.IssuerName)
		if identity.Tenant != "" {
			add(prefix+"tenant", identity.Tenant)
		}
		if len(identity.Scopes) > 0 {
			add(prefix+"scopes", strings.Join(identity.Scopes, " "))
		}
		for name, value := range identity.Forwarded {
			add(prefix+"claim-"+strings.ToLower(name), value)
		}
	}

	// Anything left in the forwarded namespace that this decision did not set
	// is stripped, so a caller cannot hand the upstream an identity of its own
	// choosing on a route where none was established.
	//
	// The headers this decision does set are excluded from the removal list.
	// Envoy applies headers_to_remove after the headers it adds, so listing a
	// header in both places deletes the value that was just written, and the
	// upstream sees no identity at all.
	for _, name := range forwardedInbound(headers, prefix) {
		if !set[name] {
			response.HeadersToRemove = append(response.HeadersToRemove, name)
		}
	}

	return &authv3.CheckResponse{
		Status:          &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse:    &authv3.CheckResponse_OkResponse{OkResponse: response},
		DynamicMetadata: dynamicMetadata(d),
	}
}

func (s *Server) deniedResponse(d decision) *authv3.CheckResponse {
	status := d.status
	if status == 0 {
		status = http.StatusForbidden
	}

	body, err := json.Marshal(map[string]string{
		"error":  string(d.reason),
		"status": strconv.Itoa(status),
	})
	if err != nil {
		body = []byte(`{"error":"internal_error"}`)
	}

	denied := &authv3.DeniedHttpResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode(status)},
		Body:   string(body),
		Headers: []*corev3.HeaderValueOption{
			header("content-type", "application/json"),
		},
	}
	if d.challenge != "" {
		denied.Headers = append(denied.Headers, header("www-authenticate", d.challenge))
	}

	return &authv3.CheckResponse{
		// PermissionDenied is what makes Envoy use the response below rather
		// than synthesizing its own.
		Status:          &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse:    &authv3.CheckResponse_DeniedResponse{DeniedResponse: denied},
		DynamicMetadata: dynamicMetadata(d),
	}
}

// dynamicMetadata publishes the decision to the rest of the filter chain, so
// access logs and downstream filters can record the tenant without re-parsing
// the token.
func dynamicMetadata(d decision) *structpb.Struct {
	fields := map[string]any{
		"rule":   d.rule,
		"reason": string(d.reason),
	}
	if d.identity != nil {
		fields["subject"] = d.identity.Subject
		fields["issuer"] = d.identity.IssuerName
		if d.identity.Tenant != "" {
			fields["tenant"] = d.identity.Tenant
		}
	}
	metadata, err := structpb.NewStruct(fields)
	if err != nil {
		return nil
	}
	return metadata
}

// forwardedInbound lists the inbound headers in the forwarded namespace, which
// are the ones the caller must not be allowed to set.
func forwardedInbound(headers map[string]string, prefix string) []string {
	var names []string
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			names = append(names, name)
		}
	}
	return names
}

func header(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: key, Value: value},
		// Overwrite rather than append, so a header this service sets has
		// exactly one value no matter what arrived.
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}
