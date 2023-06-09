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
	if l == 1 {
		return lb.IPs[0]
	}

	p := int(atomic.AddUint32(&lb.current, 1)) % l
	for k := 0; k < l; k++ { // try gets not bad address
		i := (p + k) % l
		ip = lb.IPs[i]
		if !badAddr.IsBad(ip) {
			return
		}
	}
	return lb.IPs[p] // all bad, return first
}
