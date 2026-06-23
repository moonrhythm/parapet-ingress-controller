package main

import "testing"

func TestParseBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		// bare number = bytes (backward compatible with the old envInt64 values)
		{"1", 1},
		{"1073741824", 1 << 30},
		{"1024b", 1024},
		// decimal units (1000ⁿ)
		{"2kb", 2000},
		{"512mb", 512_000_000},
		{"1gb", 1_000_000_000},
		{"3tb", 3_000_000_000_000},
		// binary units (1024ⁿ)
		{"2kib", 2 << 10},
		{"8mib", 8 << 20},
		{"1gib", 1 << 30},
		{"2gib", 2 << 30},
		{"1tib", 1 << 40},
		// case-insensitive + surrounding/inner whitespace
		{"1GiB", 1 << 30},
		{"  4 GB  ", 4_000_000_000},
		{"512MiB", 512 << 20},
		// fractional
		{"1.5gib", 1<<30 + 1<<29},
		{"0.5gb", 500_000_000},
	}
	for _, c := range cases {
		got, err := parseBytes(c.in)
		if err != nil {
			t.Errorf("parseBytes(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseBytes(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseBytes_Errors(t *testing.T) {
	for _, in := range []string{"", "  ", "abc", "10xb", "gib", "1pb", "0", "-5mb", "0.4b"} {
		if got, err := parseBytes(in); err == nil {
			t.Errorf("parseBytes(%q) = %d, want error", in, got)
		}
	}
}
