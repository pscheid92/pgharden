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
		{"::1/128", 1},
		// Netmask format
		{"192.168.1.0 255.255.255.0", 256},
		{"10.0.0.0 255.0.0.0", 16777216},
		{"172.16.0.0 255.255.0.0", 65536},
		{"192.168.0.0 255.255.128.0", 32768},
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

func TestNetworkSizeInvalid(t *testing.T) {
	_, err := NetworkSize("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
