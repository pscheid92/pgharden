package netmask

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NetworkSize returns the number of addresses in a CIDR or "IP netmask" range.
func NetworkSize(cidr string) (uint64, error) {
	// Convert "192.168.1.0 255.255.255.0" → "192.168.1.0/24"
	if !strings.Contains(cidr, "/") && strings.Contains(cidr, " ") {
		parts := strings.Fields(cidr)
		if len(parts) == 2 {
			m := net.ParseIP(parts[1])
			if m == nil {
				return 0, fmt.Errorf("invalid netmask %q", parts[1])
			}
			ones, _ := net.IPMask(m.To4()).Size()
			if ones == 0 {
				ones, _ = net.IPMask(m.To16()).Size()
			}
			cidr = fmt.Sprintf("%s/%d", parts[0], ones)
		}
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}

	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits <= 0 {
		return 1, nil
	}
	if hostBits > 63 {
		return ^uint64(0), nil
	}
	return 1 << uint(hostBits), nil
}
