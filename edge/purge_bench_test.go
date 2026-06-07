package edge

import (
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet/pkg/cache"
)

// BenchmarkInvalidatedAfter_NoPurge measures the cache-hit hook on an edge that
// caches but has never been issued a purge (the common case) — the atomic `active`
// gate should make this allocation-free and lock-free.
func BenchmarkInvalidatedAfter_NoPurge(b *testing.B) {
	tbl, _ := NewPurgeTable("", 0)
	r := httptest.NewRequest("GET", "http://acme.com/blog/post-1?utm=x", nil)
	m := cache.Meta{Host: "acme.com", URI: "/blog/post-1?utm=x", Tags: []string{"product-42", "category-shoes"}}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int64
	for i := 0; i < b.N; i++ {
		sink = tbl.InvalidatedAfter(r, m)
	}
	_ = sink
}

// BenchmarkInvalidatedAfter_WithPurges measures the same hook once purges are
// active across all four scopes — the full RLock + urlKey(sha256) + prefix/tag
// scan path the gate skips in the no-purge case.
func BenchmarkInvalidatedAfter_WithPurges(b *testing.B) {
	tbl, _ := NewPurgeTable("", 0)
	_ = tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeHost, Host: "other.com"},
		{Seq: 2, Scope: ScopeURL, Host: "acme.com", URI: "/x"},
		{Seq: 3, Scope: ScopePrefix, Host: "acme.com", URI: "/docs"},
		{Seq: 4, Scope: ScopeTag, Tag: "sku-9"},
	}, 4)
	r := httptest.NewRequest("GET", "http://acme.com/blog/post-1?utm=x", nil)
	m := cache.Meta{Host: "acme.com", URI: "/blog/post-1?utm=x", Tags: []string{"product-42", "category-shoes"}}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int64
	for i := 0; i < b.N; i++ {
		sink = tbl.InvalidatedAfter(r, m)
	}
	_ = sink
}
