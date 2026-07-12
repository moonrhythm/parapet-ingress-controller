//go:build !unix

package edge

// diskUsage is unavailable on non-unix platforms (the edge ships for linux/* only).
func diskUsage(path string) (size, available uint64, ok bool) {
	return 0, 0, false
}
