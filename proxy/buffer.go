package proxy

import (
	"sync"
)

const bufferSize = 16 * 1024

type bufferPool struct {
	sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{
		Pool: sync.Pool{
			New: func() any { return make([]byte, bufferSize) },
		},
	}
}

func (p *bufferPool) Get() []byte {
	return p.Pool.Get().([]byte)
}

func (p *bufferPool) Put(b []byte) {
	p.Pool.Put(b)
}
