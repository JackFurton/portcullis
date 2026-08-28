package policy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Request is the part of an inbound request a rule can match on.
type Request struct {
	// Host is the :authority value, port included if the client sent one.
	Host string
	// Method is the HTTP method.
	Method string
	// Path is the :path value, query string included.
	Path string
}

// ErrMalformedPath means the path could not be reduced to something safe to
// match a prefix against.
var ErrMalformedPath = errors.New("malformed path")

// NormalizePath reduces a :path value to the path a rule matches against, and
// refuses anything it cannot reduce safely.
//
// Rejecting is the right move rather than cleaning up. A rule granting
// /v1/public and denying /v1/admin is only meaningful if the path the rule sees
// is the path the upstream will route on. Encoded slashes, dot segments and
// backslashes are the three ways those two disagree, and no legitimate client
// needs any of them: Envoy's own path normalization removes them before this
// service is ever called, so seeing one means either normalization is off or
// someone is trying.
func NormalizePath(path string) (string, error) {
	raw, _, _ := strings.Cut(path, "?")
	raw, _, _ = strings.Cut(raw, "#")

	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: %q does not start with a slash", ErrMalformedPath, path)
	}

	// An encoded slash has to be caught before decoding: afterwards it is
	// indistinguishable from a real segment boundary, which is the whole trick.
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", fmt.Errorf("%w: %q contains an encoded separator", ErrMalformedPath, path)
	}

	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not valid percent encoding", ErrMalformedPath, path)
	}
	if strings.Contains(decoded, `\`) {
		return "", fmt.Errorf("%w: %q contains a backslash", ErrMalformedPath, path)
	}
	if strings.Contains(decoded, "//") {
		return "", fmt.Errorf("%w: %q contains an empty segment", ErrMalformedPath, path)
	}
	for segment := range strings.SplitSeq(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: %q contains a dot segment", ErrMalformedPath, path)
		}
	}
	return decoded, nil
}

// Match finds the first rule that applies to a request. The path must already
// be normalized. A request matching no rule has no rule, and the caller denies
// it: the absence of a match is the default deny.
func (c *Config) Match(req Request, normalizedPath string) (*Rule, bool) {
	for i := range c.Rules {
		if c.Rules[i].Match.matches(req, normalizedPath) {
			return &c.Rules[i], true
		}
	}
	return nil, false
}

func (m *Match) matches(req Request, path string) bool {
	if len(m.Methods) > 0 && !containsFold(m.Methods, req.Method) {
		return false
	}
	if len(m.Hosts) > 0 && !matchHost(m.Hosts, req.Host) {
		return false
	}
	if len(m.PathsExact) == 0 && len(m.PathPrefixes) == 0 {
		return true
	}
	for _, exact := range m.PathsExact {
		if path == exact {
			return true
		}
	}
	for _, prefix := range m.PathPrefixes {
		if matchPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// matchPrefix requires the prefix to end at a segment boundary, so a rule for
// /v1/admin does not also cover /v1/administrators.
func matchPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) || strings.HasSuffix(prefix, "/") {
		return true
	}
	return path[len(prefix)] == '/'
}

// matchHost compares against :authority with any port removed. A pattern
// starting with "*." matches any host under that suffix, but not the suffix
// itself: *.example.com covers api.example.com, not example.com.
func matchHost(patterns []string, authority string) bool {
	host := authority
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	host = strings.ToLower(strings.Trim(host, "[]"))

	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
