package edgecp

import "strconv"

// The trust-bundle generation is the resourceVersion of the SINGLE source object whose
// change moves trust: the parapet-edge-ca Secret. etcd assigns one global, monotonic
// revision, so every CP replica's List/Watch of that SAME object returns the SAME
// resourceVersion — the generation is therefore replica-identical and monotonic BY
// CONSTRUCTION, replacing the old per-process prev+1 counter that two replicas desync.
//
// It is deliberately NOT a max() across multiple objects. A k8s resourceVersion is
// meaningful ONLY within one object's history (the etcd revision at which THAT object
// last changed); maxing the resourceVersions of two DIFFERENT objects compares
// incomparable values and can regress on one replica. When the token registry becomes a
// Secret, it gets its OWN separate generation for its OWN concern (the authz barrier) —
// it must NEVER be folded into this generation. DO NOT add a maxGen(...uint64) helper
// here; that API shape invites exactly the broken cross-object max().

// rvToU64 converts a Kubernetes resourceVersion to the uint64 generation. A
// resourceVersion is normally the decimal etcd revision (client-go formats an int64), so
// it parses cleanly — but the API contract explicitly permits an OPAQUE, non-numeric
// value (a future or aggregated apiserver). On non-numeric/empty/overflow it returns
// ok=false and the caller MUST keep last-good and surface it loudly; it must NEVER fall
// back to 0 or a process counter, since a low generation would let a replayed-older
// bundle win the core's forward-only anti-rollback check.
func rvToU64(rv string) (uint64, bool) {
	if rv == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(rv, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
