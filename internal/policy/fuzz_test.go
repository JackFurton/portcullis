package policy_test

import (
	"strings"
	"testing"

	"github.com/JackFurton/portcullis/internal/policy"
)

// Path normalization decides which rule a request matches, which makes it the
// place an authorization bypass would live. The table tests cover the cases I
// thought of; this covers the ones I did not.
//
// The assertions are properties rather than expected outputs. If a path
// normalizes at all, the result has to be something a prefix can be matched
// against safely, whatever the input was.
func FuzzNormalizePath(f *testing.F) {
	seeds := []string{
		"/v1/events",
		"/v1/events?since=1",
		"/v1/events#top",
		"/v1/admin/../public",
		"/v1/public/%2f..%2fadmin",
		"/v1/public/%2F..%2Fadmin",
		"/v1/public/%2e%2e/admin",
		"/v1%5cadmin",
		`/v1\admin`,
		"/v1//admin",
		"/v1/./admin",
		"/v1/%zz",
		"/v1/public%252fadmin",
		"/0%2520",
		"/%25",
		"/v1/%",
		"/v1/%2",
		"v1/events",
		"",
		"/",
		"//",
		"/%00",
		"/v1/événements",
		"/v1/events%20with%20spaces",
		strings.Repeat("/a", 200),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		got, err := policy.NormalizePath(path)
		if err != nil {
			// Rejecting is always a safe answer. The interesting failures are
			// paths that are accepted and should not be.
			return
		}

		if !strings.HasPrefix(got, "/") {
			t.Fatalf("NormalizePath(%q) = %q, which does not start with a slash", path, got)
		}
		for _, forbidden := range []string{"//", `\`, "%2f", "%2F", "%5c", "%5C"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("NormalizePath(%q) = %q, which still contains %q", path, got, forbidden)
			}
		}
		for segment := range strings.SplitSeq(got, "/") {
			if segment == "." || segment == ".." {
				t.Fatalf("NormalizePath(%q) = %q, which still contains a dot segment", path, got)
			}
		}
		if strings.ContainsAny(got, "?#") {
			t.Fatalf("NormalizePath(%q) = %q, which still carries a query or fragment", path, got)
		}

		// Normalizing an already normalized path must return it unchanged.
		// A path that becomes something else on a second pass is a path whose
		// meaning depends on how many times it has been processed, which is
		// the whole class of bug this function exists to prevent.
		again, err := policy.NormalizePath(got)
		if err != nil {
			t.Fatalf("NormalizePath(%q) = %q, which then fails to normalize: %v", path, got, err)
		}
		if again != got {
			t.Fatalf("NormalizePath is not idempotent: %q became %q became %q", path, got, again)
		}
	})
}
