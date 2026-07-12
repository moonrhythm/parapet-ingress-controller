//go:build !(linux || darwin)

package edge

// diskUsage is unavailable outside linux/darwin (the edge ships for linux/*;
// darwin is for local dev). Other GOOS get a quiet omit of the disk series.
func diskUsage(path string) (size, available uint64, ok bool) {
	return 0, 0, false
}
