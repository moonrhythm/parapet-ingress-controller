package wsh2

import (
	"io"
	"sync"
)

const bufferSize = 16 * 1024

var bufferPool = sync.Pool{
	New: func() any { b := make([]byte, bufferSize); return &b },
}

// Copy streams src to dst using a pooled buffer, calling flush (when non-nil)
// after every write. The flush hook is what makes the pod→client direction of a
// spliced tunnel usable: an h2 ResponseWriter buffers writes, so a WebSocket
// frame must be flushed to reach the peer instead of waiting for more bytes. The
// client→pod direction writes to a raw net.Conn and passes a nil flush.
//
// Copy returns nil on a clean EOF from src, or the first read/write error.
// Callers close both endpoints when it returns so the opposite direction
// unblocks.
func Copy(dst io.Writer, src io.Reader, flush func()) error {
	bp := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bp)
	buf := *bp

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if flush != nil {
				flush()
			}
			if ew != nil {
				return ew
			}
			if nw < nr {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return nil
			}
			return er
		}
	}
}
