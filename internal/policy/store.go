package policy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/yaml"
)

// Load reads and validates a policy file. Unknown fields are an error: a typo
// in a rule name is a broken rule, and a typo in "tenants" is a rule that
// silently stops checking the tenant.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(raw)
}

// Parse validates policy bytes.
func Parse(raw []byte) (*Config, error) {
	var config Config
	if err := yaml.UnmarshalStrict(raw, &config); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &config, nil
}

// Store holds the policy currently in force and swaps in new versions as the
// file changes. Readers take the pointer once per request; there is no lock in
// the request path.
type Store struct {
	path    string
	log     *slog.Logger
	current atomic.Pointer[Config]

	// OnReload is called after a new policy is applied. The service uses it to
	// warm the key sets for any issuer that was just added.
	OnReload func(*Config)

	// OnReloadError is called when a reload was rejected and the previous
	// policy is still in force.
	OnReloadError func(error)

	// reloads counts successful reloads, for the metric and for tests.
	reloads atomic.Int64
	// failures counts reloads that were rejected.
	failures atomic.Int64
}

// NewStore loads the policy once. A policy that does not validate is a startup
// failure, not a warning.
func NewStore(path string, log *slog.Logger) (*Store, error) {
	config, err := Load(path)
	if err != nil {
		return nil, err
	}
	store := &Store{path: path, log: log}
	store.current.Store(config)
	return store, nil
}

// Config returns the policy in force.
func (s *Store) Config() *Config { return s.current.Load() }

// Reloads reports how many times a new policy has been applied.
func (s *Store) Reloads() int64 { return s.reloads.Load() }

// Failures reports how many reload attempts were rejected.
func (s *Store) Failures() int64 { return s.failures.Load() }

// Reload re-reads the file and applies it if it validates.
//
// A policy that fails to parse leaves the previous one in force. The
// alternative, dropping to an empty policy, turns a YAML typo into a total
// outage; keeping the last good policy turns it into a stale one plus a loud
// log line and a metric someone can alert on.
func (s *Store) Reload() error {
	config, err := Load(s.path)
	if err != nil {
		s.failures.Add(1)
		if s.OnReloadError != nil {
			s.OnReloadError(err)
		}
		return err
	}
	s.current.Store(config)
	s.reloads.Add(1)
	if s.OnReload != nil {
		s.OnReload(config)
	}
	return nil
}

// debounce is how long to wait after a filesystem event before reloading.
// Writers are rarely atomic, and reading halfway through one is a guaranteed
// parse failure.
const debounce = 250 * time.Millisecond

// Watch reloads the policy when the file changes, until the context is done.
//
// It watches the containing directory rather than the file. A ConfigMap
// mounted into a pod is a symlink into a "..data" directory that Kubernetes
// swaps wholesale on update, so the inode the file pointed at when the watch
// started is not the one that changes. Watching the file directly works on a
// laptop and silently never fires in a cluster.
func (s *Store) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	dir := filepath.Dir(s.path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	s.log.Info("watching policy for changes", "path", s.path, "dir", dir)

	var timer *time.Timer
	var pending <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !s.relevant(event) {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(debounce)
			pending = timer.C

		case <-pending:
			pending = nil
			if err := s.Reload(); err != nil {
				s.log.Error("policy reload rejected, keeping the previous policy", "error", err)
				continue
			}
			s.log.Info("policy reloaded", "path", s.path, "rules", len(s.Config().Rules))

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			s.log.Error("policy watcher error", "error", err)
		}
	}
}

// relevant reports whether an event could mean the policy changed. The
// "..data" name is the directory Kubernetes swaps when a mounted ConfigMap is
// updated.
func (s *Store) relevant(event fsnotify.Event) bool {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
		return false
	}
	base := filepath.Base(event.Name)
	return base == filepath.Base(s.path) || base == "..data"
}
