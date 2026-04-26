package types

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

// IP represents a validated IP address (v4 or v6).
type IP struct {
	raw net.IP
	v6  bool
}

// NewIP creates a validated IP from a string.
func NewIP(raw string) (IP, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return IP{}, fmt.Errorf("IP cannot be empty")
	}

	parsed := net.ParseIP(raw)
	if parsed == nil {
		return IP{}, fmt.Errorf("invalid IP address: %q", raw)
	}

	isV6 := parsed.To4() == nil
	return IP{raw: parsed, v6: isV6}, nil
}

// ValidateIP validates a raw IP string.
func ValidateIP(raw string) error {
	_, err := NewIP(raw)
	return err
}

// String returns the IP as a string.
func (ip IP) String() string { return ip.raw.String() }

// IsV4 returns true if this is an IPv4 address.
func (ip IP) IsV4() bool { return !ip.v6 }

// IsV6 returns true if this is an IPv6 address.
func (ip IP) IsV6() bool { return ip.v6 }

// IsPrivate returns true if this is a private/reserved IP.
func (ip IP) IsPrivate() bool { return ip.raw.IsPrivate() }

// IsLoopback returns true if this is a loopback address.
func (ip IP) IsLoopback() bool { return ip.raw.IsLoopback() }

// Net returns the underlying net.IP.
func (ip IP) Net() net.IP { return ip.raw }

// CIDR represents a validated CIDR block.
type CIDR struct {
	raw     string
	network *net.IPNet
}

// NewCIDR creates a validated CIDR from a string like "192.168.1.0/24".
func NewCIDR(raw string) (CIDR, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return CIDR{}, fmt.Errorf("CIDR cannot be empty")
	}

	_, network, err := net.ParseCIDR(raw)
	if err != nil {
		return CIDR{}, fmt.Errorf("invalid CIDR: %q: %w", raw, err)
	}

	return CIDR{raw: network.String(), network: network}, nil
}

// ValidateCIDR validates a raw CIDR string.
func ValidateCIDR(raw string) error {
	_, err := NewCIDR(raw)
	return err
}

// String returns the CIDR as a string.
func (c CIDR) String() string { return c.raw }

// Contains returns true if the given IP is within this CIDR block.
func (c CIDR) Contains(ip IP) bool {
	return c.network.Contains(ip.raw)
}

// Network returns the network address.
func (c CIDR) Network() net.IP {
	return c.network.IP
}

// Mask returns the network mask.
func (c CIDR) Mask() net.IPMask {
	return c.network.Mask
}

// PrefixLen returns the prefix length (e.g., 24 for /24).
func (c CIDR) PrefixLen() int {
	ones, _ := c.network.Mask.Size()
	return ones
}

// HostCount returns the number of host addresses in the CIDR block.
func (c CIDR) HostCount() *big.Int {
	ones, bits := c.network.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return big.NewInt(1)
	}
	count := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	// Subtract 2 for network and broadcast (IPv4 only, and only if > /31)
	if bits == 32 && hostBits > 1 {
		count.Sub(count, big.NewInt(2))
	}
	return count
}

// IPNet returns the underlying net.IPNet.
func (c CIDR) IPNet() *net.IPNet {
	return c.network
}
