package metric

import "testing"

// BenchmarkTrustSource proves the per-request hot-path cost is a single atomic add on
// a pre-materialized handle — no lock, no label resolution, zero allocs.
func BenchmarkTrustSource(b *testing.B) {
	TrustSource("verified-chain") // warm
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TrustSource("verified-chain")
	}
}
