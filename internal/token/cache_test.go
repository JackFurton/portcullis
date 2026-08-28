package token

import (
	"testing"
	"time"
)

func identity(expiresIn time.Duration) *Identity {
	return &Identity{Subject: "user-1", ExpiresAt: time.Now().Add(expiresIn)}
}

func TestCacheReturnsAStoredIdentity(t *testing.T) {
	cache := newVerifiedCache(10)
	now := time.Now()

	cache.put("k", identity(time.Hour), now)

	got, ok := cache.get("k", now, 0)
	if !ok {
		t.Fatal("expected a hit")
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", got.Subject, "user-1")
	}
}

// Expiry is enforced on every hit, not at insertion, so a cached result can
// never outlive the token it came from.
func TestCacheDropsAnExpiredToken(t *testing.T) {
	cache := newVerifiedCache(10)
	now := time.Now()

	cache.put("k", identity(-time.Minute), now)

	if _, ok := cache.get("k", now, 0); ok {
		t.Fatal("an expired token must not be served from the cache")
	}
	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want the dead entry evicted", cache.Len())
	}
}

// A long lived token should not coast on a result computed hours ago: the
// issuer's configuration or keys may have changed in the meantime.
func TestCacheStopsReusingAnOldResult(t *testing.T) {
	cache := newVerifiedCache(10)
	verifiedAt := time.Now().Add(-2 * maxCacheAge)

	cache.put("k", identity(time.Hour), verifiedAt)

	if _, ok := cache.get("k", time.Now(), 0); ok {
		t.Fatal("a result older than the maximum age must be recomputed")
	}
}

// The bound is what stops a flood of distinct tokens from becoming a memory
// exhaustion bug.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := newVerifiedCache(3)
	now := time.Now()

	for _, key := range []string{"a", "b", "c"} {
		cache.put(key, identity(time.Hour), now)
	}
	// Touch "a" so "b" becomes the oldest.
	if _, ok := cache.get("a", now, 0); !ok {
		t.Fatal("expected a hit for a")
	}
	cache.put("d", identity(time.Hour), now)

	if cache.Len() != 3 {
		t.Errorf("Len() = %d, want 3", cache.Len())
	}
	if _, ok := cache.get("b", now, 0); ok {
		t.Error("b was the least recently used and should have been evicted")
	}
	for _, key := range []string{"a", "c", "d"} {
		if _, ok := cache.get(key, now, 0); !ok {
			t.Errorf("%s should still be cached", key)
		}
	}
}

// A reload can change an issuer's audiences, algorithms or claim mapping, so
// results computed under the old configuration have to go.
func TestFlushDropsEverything(t *testing.T) {
	cache := newVerifiedCache(10)
	now := time.Now()
	cache.put("k", identity(time.Hour), now)

	cache.Flush()

	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want 0", cache.Len())
	}
	if _, ok := cache.get("k", now, 0); ok {
		t.Error("expected a miss after a flush")
	}
}

// The cache key must not be the token. This map is exactly the sort of thing
// that ends up in a heap dump.
// A cache size of zero turns every lookup into a miss, which is how an
// operator opts out of holding identities in memory.
func TestCacheCanBeDisabled(t *testing.T) {
	cache := newVerifiedCache(0)
	now := time.Now()

	cache.put("k", identity(time.Hour), now)

	if _, ok := cache.get("k", now, 0); ok {
		t.Error("a disabled cache must never hit")
	}
	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want 0", cache.Len())
	}
}

func TestCacheKeyDoesNotContainTheToken(t *testing.T) {
	raw := "eyJhbGciOiJSUzI1NiJ9.payload.signature"

	key := cacheKey("corp", raw)

	if len(key) != 64 {
		t.Errorf("key length = %d, want a 64 character hex digest", len(key))
	}
	if key == raw || len(key) >= len(raw) && contains(key, "payload") {
		t.Error("the cache key must be a digest, not the token")
	}
	if cacheKey("other", raw) == key {
		t.Error("the same token under a different issuer must key differently")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
