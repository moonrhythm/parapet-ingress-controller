// Package wafclaim defines the edge→core "WAF already validated" claim: the
// request header the edge proxy stamps after its WAF layer evaluated a request,
// and which the core requires — in addition to the peer matching
// WAF_VALIDATED_PROXY — before skipping its own WAF. Sharing the constant pins
// the wire contract; the stamping (edge), stripping (edge), and
// require-then-sanitize (core) logic live with each binary.
package wafclaim

// Header carries the per-request claim. The edge sets it (overwriting any
// inbound value) only once a control-plane WAF snapshot has applied cleanly;
// its value is that snapshot's generation, for debugging — the core checks
// only presence. Trust contract: the header is meaningful only on a hop whose
// peer the core verified (edge client cert / listed CIDR); the edge strips
// client-supplied values unconditionally, and a core with the skip enabled
// (WAF_ENABLED + WAF_VALIDATED_PROXY) drops the header from any request it
// did not skip, so an unvalidated claim never reaches CEL rules, the zone
// WAF, or the upstream backend there. A core with the skip DISABLED never
// reads nor strips it (disabled features do no per-request work) — backends
// must not trust the header unless the core in front of them has it enabled.
const Header = "X-Parapet-Waf"
