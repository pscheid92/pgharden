package netmask

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
)

// NetworkSize returns the number of addresses in a CIDR range.
// Accepts "192.168.1.0/24" or "192.168.1.0 255.255.255.0" format.
func NetworkSize(cidr string) (uint64, error) {
	// Handle "IP netmask" format
	if !strings.Contains(cidr, "/") && strings.Contains(cidr, " ") {
		parts := strings.Fields(cidr)
		if len(parts) == 2 {
			prefix, err := netmaskToPrefix(parts[0], parts[1])
			if err != nil {
				return 0, err
			}
			cidr = prefix
		}
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}

	bits := prefix.Addr().BitLen() // 32 for IPv4, 128 for IPv6
	hostBits := bits - prefix.Bits()
	if hostBits <= 0 {
		return 1, nil
	}
	if hostBits > 63 {
		// Very large range, cap at max uint64
		return ^uint64(0), nil
	}
	return 1 << uint(hostBits), nil
}

// ParseCIDR parses a CIDR string and returns the prefix.
func ParseCIDR(cidr string) (netip.Prefix, error) {
	// Handle "IP netmask" format
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
	maskAddr, err := netip.ParseAddr(mask)
	if err != nil {
		return "", fmt.Errorf("parsing netmask %q: %w", mask, err)
	}

	// Use the native-size byte representation to avoid IPv4-in-IPv6 mapping issues.
	var maskBytes []byte
	if maskAddr.Is4() {
		b := maskAddr.As4()
		maskBytes = b[:]
	} else {
		b := maskAddr.As16()
		maskBytes = b[:]
	}

	// Count leading 1-bits across all bytes.
	prefix := 0
	for _, b := range maskBytes {
		if b == 0xff {
			prefix += 8
			continue
		}
		// Count leading ones in this byte, then stop — a valid netmask
		// has no more 1-bits after the first 0-bit.
		prefix += bits.LeadingZeros8(^b)
		break
	}

	return fmt.Sprintf("%s/%d", ip, prefix), nil
}
