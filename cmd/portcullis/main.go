// Command portcullis is an external authorization service for Envoy and Istio.
//
// It answers the ext_authz Check RPC: given the method, host and path of a
// request and the bearer token on it, decide whether the request proceeds, and
// tell the upstream who is calling.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/JackFurton/portcullis/internal/authz"
	"github.com/JackFurton/portcullis/internal/metrics"
	"github.com/JackFurton/portcullis/internal/policy"
	"github.com/JackFurton/portcullis/internal/token"
	"github.com/JackFurton/portcullis/internal/version"
)

func main() {
	var (
		policyPath = flag.String("policy", "/etc/portcullis/policy.yaml", "path to the policy file")
		grpcAddr   = flag.String("grpc-addr", ":9191", "address for the ext_authz gRPC service")
		adminAddr  = flag.String("admin-addr", ":9192", "address for metrics and health")
		logLevel   = flag.String("log-level", "info", "one of debug, info, warn, error")
		logFormat  = flag.String("log-format", "json", "json or text")
		cacheSize  = flag.Int("token-cache-size", token.DefaultCacheSize,
			"how many verified tokens to remember; 0 disables the cache and verifies every request")
		checkOnly = flag.Bool("check", false, "validate the policy file and exit")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String())
		return
	}

	log := newLogger(*logLevel, *logFormat)

	if *checkOnly {
		// Worth having in CI: the policy is the security control, and a broken
		// one should fail a pipeline rather than a rollout.
		config, err := policy.Load(*policyPath)
		if err != nil {
			log.Error("policy is not valid", "path", *policyPath, "error", err)
			os.Exit(1)
		}
		fmt.Printf("policy ok: %d issuers, %d rules, failureMode=%s\n",
			len(config.Issuers), len(config.Rules), config.FailureMode)
		return
	}

	if err := run(*policyPath, *grpcAddr, *adminAddr, *cacheSize, log); err != nil {
		log.Error("shutting down", "error", err)
		os.Exit(1)
	}
}

func run(policyPath, grpcAddr, adminAddr string, cacheSize int, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version.String())

	store, err := policy.NewStore(policyPath, log)
	if err != nil {
		return err
	}
	config := store.Config()
	log.Info("policy loaded",
		"path", policyPath,
		"issuers", len(config.Issuers),
		"rules", len(config.Rules),
		"failureMode", config.FailureMode,
	)

	keys := token.NewKeyCache(&http.Client{Timeout: 5 * time.Second}, log)
	keys.Warm(ctx, config)

	verifier := token.NewVerifier(keys, cacheSize)

	store.OnReload = func(config *policy.Config) {
		metrics.PolicyReloads.WithLabelValues("success").Inc()
		// A reload can change an issuer's audiences, algorithms or claim
		// mapping, so results verified under the old policy are discarded.
		verifier.Flush()
		// A reload can add an issuer. Fetching its keys now keeps the first
		// request that needs them off the critical path.
		keys.Warm(ctx, config)
	}
	store.OnReloadError = func(error) {
		metrics.PolicyReloads.WithLabelValues("error").Inc()
	}

	server := authz.NewServer(store, verifier, log)

	grpcServer := grpc.NewServer(
		// Envoy holds one long lived connection per proxy. Without these the
		// server never notices a proxy that vanished, and a rolling restart of
		// the mesh leaves connections that are never cleaned up.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	authv3.RegisterAuthorizationServer(grpcServer, server)

	healthServer := health.NewServer()
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", grpcAddr, err)
	}

	admin := &http.Server{
		Addr:              adminAddr,
		Handler:           adminHandler(store),
		ReadHeaderTimeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("ext_authz listening", "addr", grpcAddr)
		if err := grpcServer.Serve(listener); err != nil {
			errs <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("admin listening", "addr", adminAddr)
		if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("admin server: %w", err)
		}
	}()

	go func() {
		if err := store.Watch(ctx); err != nil {
			log.Error("policy watcher stopped", "error", err)
		}
	}()
	go keys.Refresh(ctx, store)

	select {
	case err := <-errs:
		stop()
		grpcServer.Stop()
		_ = admin.Close()
		wg.Wait()
		return err
	case <-ctx.Done():
	}

	log.Info("draining")
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.Shutdown(shutdown); err != nil {
		log.Warn("admin shutdown", "error", err)
	}

	// GracefulStop lets in-flight checks finish. Cutting them off would show
	// up downstream as failed requests during every deploy.
	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-shutdown.Done():
		grpcServer.Stop()
	}

	wg.Wait()
	return nil
}

func adminHandler(store *policy.Store) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if store.Config() == nil {
			http.Error(w, "no policy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func newLogger(level, format string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToLower(level))); err != nil {
		l = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: l}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}
