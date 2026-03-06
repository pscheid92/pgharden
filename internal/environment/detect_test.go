package environment

import "testing"

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"PostgreSQL 16.4 on x86_64-pc-linux-gnu", 16},
		{"PostgreSQL 15.2 (Ubuntu 15.2-1.pgdg22.04+1)", 15},
		{"PostgreSQL 14.10 on aarch64-unknown-linux-gnu", 14},
		{"PostgreSQL 9.6.24 on x86_64-pc-linux-gnu", 9},
		{"something else entirely", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMajorVersion(tt.input)
			if got != tt.want {
				t.Errorf("parseMajorVersion(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
