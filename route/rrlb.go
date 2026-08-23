package route

import (
	"sync/atomic"
)

// RRLB is round-robin load balancer
type RRLB struct {
	IPs     []string // immutable
	current uint32
}

func (lb *RRLB) Get(badAddr *badAddrTable) (ip string) {
	l := len(lb.IPs)
	if l == 0 {
		return ""
	}

	// take the modulo in uint32 space: int(uint32) can be negative on 32-bit
	// platforms once current exceeds MaxInt32, which would yield a negative index.
	p := int(atomic.AddUint32(&lb.current, 1) % uint32(l))
	for k := range l { // try gets not bad address
		i := (p + k) % l
		ip = lb.IPs[i]
		if !badAddr.IsBad(ip) {
			return
		}
	}
	// every replica is marked bad (including a lone replica): return empty so
	// Lookup 503s instead of dialing a known-dead target and pinning the request.
	return ""
}
