// Command echo is the upstream in the demo. It reports what actually arrived,
// which is the only way to see that the identity headers were set by the
// authorization service and not by the caller.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "address to listen on")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Every path is echoed, including /healthz. The demo policy makes
	// /healthz public, and seeing the same body there as everywhere else is
	// what shows that "public" means no identity rather than no upstream.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		identity := map[string]string{}
		var others []string
		for name, values := range r.Header {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-portcullis-") {
				identity[lower] = strings.Join(values, ",")
				continue
			}
			others = append(others, lower)
		}
		sort.Strings(others)

		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(map[string]any{
			"upstream":     "echo",
			"method":       r.Method,
			"path":         r.URL.Path,
			"identity":     identity,
			"otherHeaders": others,
			"receivedAt":   time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			log.Error("encode response", "error", err)
		}
	})

	log.Info("echo upstream listening", "addr", *addr)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
