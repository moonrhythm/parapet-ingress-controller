package route

import (
	"io"
	"log/slog"
	"strconv"
	"testing"
)

// quietLogs silences the bad-addr table's slog output (clear-loop start, mark-bad
// warnings) so it doesn't interleave with benchmark result lines.
func quietLogs() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func benchRRLB(n int) *RRLB {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = "10.0.0." + strconv.Itoa(i+1)
	}
	return &RRLB{IPs: ips}
}

// BenchmarkRouteLookup measures the full per-request route resolution: RLock + two
// map reads + RRLB round-robin + the host:port concat.
func BenchmarkRouteLookup(b *testing.B) {
	quietLogs()
	const host = "svc.ns.svc.cluster.local"
	const addr = host + ":80"
	t := &Table{}
	t.SetHostRoutes(map[string]*RRLB{host: benchRRLB(8)})
	t.SetPortRoutes(map[string]string{addr: "8080"})
	b.ReportAllocs()
	b.ResetTimer()
	var sink string
	for i := 0; i < b.N; i++ {
		sink = t.Lookup(addr)
	}
	_ = sink
}

// BenchmarkRRLBGet_AllHealthy is the common case: the first probed IP is good.
func BenchmarkRRLBGet_AllHealthy(b *testing.B) {
	lb := benchRRLB(16)
	var ba badAddrTable
	b.ReportAllocs()
	b.ResetTimer()
	var sink string
	for i := 0; i < b.N; i++ {
		sink = lb.Get(&ba)
	}
	_ = sink
}

// BenchmarkRRLBGet_HalfBad measures the linear bad-address skip under a partial
// outage (half the pods marked bad).
func BenchmarkRRLBGet_HalfBad(b *testing.B) {
	quietLogs()
	lb := benchRRLB(16)
	var ba badAddrTable
	for i := 0; i < len(lb.IPs); i += 2 {
		ba.MarkBad(lb.IPs[i])
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink string
	for i := 0; i < b.N; i++ {
		sink = lb.Get(&ba)
	}
	_ = sink
}
