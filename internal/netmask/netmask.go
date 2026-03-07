package netmask

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NetworkSize returns the number of addresses in a CIDR range.
// Accepts "192.168.1.0/24" or "192.168.1.0 255.255.255.0" format.
func NetworkSize(cidr string) (uint64, error) {
	prefix, err := ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}

	bits := prefix.Addr().BitLen() // 32 for IPv4, 128 for IPv6
	hostBits := bits - prefix.Bits()
	if hostBits <= 0 {
		return 1, nil
	}
	if hostBits > 63 {
		return ^uint64(0), nil
	}
	return 1 << uint(hostBits), nil
}

// ParseCIDR parses a CIDR or "IP netmask" string into a netip.Prefix.
func ParseCIDR(cidr string) (netip.Prefix, error) {
	if !strings.Contains(cidr, "/") && strings.Contains(cidr, " ") {
		parts := strings.Fields(cidr)
		if len(parts) == 2 {
			prefix, err := netmaskToPrefix(parts[0], parts[1])
			if err != nil {
				return netip.Prefix{}, err
			}
			cidr = prefix
		}
	}
	return netip.ParsePrefix(cidr)
}

// netmaskToPrefix converts "192.168.1.0" + "255.255.255.0" to "192.168.1.0/24".
func netmaskToPrefix(ip, mask string) (string, error) {
	m := net.ParseIP(mask)
	if m == nil {
		return "", fmt.Errorf("invalid netmask %q", mask)
	}

	// net.IPMask.Size() returns the prefix length directly.
	ones, _ := net.IPMask(m.To4()).Size()
	if ones == 0 {
		// Try as IPv6 mask.
		ones, _ = net.IPMask(m.To16()).Size()
	}

	return fmt.Sprintf("%s/%d", ip, ones), nil
}
