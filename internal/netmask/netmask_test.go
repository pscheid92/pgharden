package netmask

import "testing"

func TestNetworkSize(t *testing.T) {
	tests := []struct {
		cidr string
		want uint64
	}{
		{"192.168.1.1/32", 1},
		{"192.168.1.0/24", 256},
		{"10.0.0.0/16", 65536},
		{"10.0.0.0/8", 16777216},
		{"0.0.0.0/0", 4294967296},
		// Netmask format
		{"192.168.1.0 255.255.255.0", 256},
		{"10.0.0.0 255.0.0.0", 16777216},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := NetworkSize(tt.cidr)
			if err != nil {
				t.Fatalf("NetworkSize(%q): %v", tt.cidr, err)
			}
			if got != tt.want {
				t.Errorf("NetworkSize(%q) = %d, want %d", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestNetworkSizeIPv6(t *testing.T) {
	got, err := NetworkSize("::1/128")
	if err != nil {
		t.Fatalf("NetworkSize(::1/128): %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"::1/128",
		"192.168.1.0 255.255.255.0",
	}

	for _, cidr := range tests {
		t.Run(cidr, func(t *testing.T) {
			_, err := ParseCIDR(cidr)
			if err != nil {
				t.Errorf("ParseCIDR(%q): %v", cidr, err)
			}
		})
	}
}

func TestNetworkSizeInvalid(t *testing.T) {
	_, err := NetworkSize("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
