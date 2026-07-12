//go:build unix

package edge

import "golang.org/x/sys/unix"

// diskUsage reports the total and unprivileged-available bytes of the filesystem
// that holds path (typically EDGE_CACHE_DIR). ok is false when statfs fails
// (missing mount, permission denied, etc.).
func diskUsage(path string) (size, available uint64, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	// Bsize is int64 on Linux and int32 on Darwin; Blocks/Bavail widths also
	// differ. Promote everything through uint64 carefully — Bavail is the free
	// space a non-root process may allocate (matches node_exporter's avail).
	bsize := uint64(st.Bsize) //nolint:unconvert // intentional width cast across GOOS
	if bsize == 0 {
		return 0, 0, false
	}
	size = uint64(st.Blocks) * bsize
	// Bavail is signed on some platforms (reserved blocks can make free < reserved).
	if st.Bavail > 0 {
		available = uint64(st.Bavail) * bsize
	}
	return size, available, true
}
