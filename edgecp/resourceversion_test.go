package edgecp

import "testing"

func TestRVToU64(t *testing.T) {
	cases := []struct {
		rv     string
		want   uint64
		wantOk bool
	}{
		{"100", 100, true},
		{"18446744073709551615", 1<<64 - 1, true}, // max uint64
		{"0", 0, true},
		{"", 0, false},                     // empty
		{"abc", 0, false},                  // opaque (aggregated apiserver)
		{"100x", 0, false},                 // trailing garbage
		{"-1", 0, false},                   // negative
		{"18446744073709551616", 0, false}, // overflow
		{"  100  ", 0, false},              // whitespace not trimmed (strict)
	}
	for _, tc := range cases {
		got, ok := rvToU64(tc.rv)
		if ok != tc.wantOk || (ok && got != tc.want) {
			t.Errorf("rvToU64(%q) = (%d,%v), want (%d,%v)", tc.rv, got, ok, tc.want, tc.wantOk)
		}
	}
}
