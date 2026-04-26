// Package types provides core domain types with validation for ReconForge.
package types

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// domainRegex validates domain names (RFC 1035 compliant).
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// wildcardDomainRegex allows wildcard domains like *.example.com.
var wildcardDomainRegex = regexp.MustCompile(`^\*\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Domain represents a validated domain name.
type Domain struct {
	raw    string
	labels []string
}

// NewDomain creates a validated Domain from a raw string.
func NewDomain(raw string) (Domain, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, ".")
	raw = strings.ToLower(raw)

	if raw == "" {
		return Domain{}, fmt.Errorf("domain cannot be empty")
	}

	if len(raw) > 253 {
		return Domain{}, fmt.Errorf("domain too long: %d chars (max 253)", len(raw))
	}

	if !domainRegex.MatchString(raw) {
		return Domain{}, fmt.Errorf("invalid domain: %q", raw)
	}

	labels := strings.Split(raw, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return Domain{}, fmt.Errorf("label too long: %q (%d chars, max 63)", label, len(label))
		}
	}

	return Domain{raw: raw, labels: labels}, nil
}

// ValidateDomain validates and normalizes a raw domain string.
func ValidateDomain(raw string) error {
	_, err := NewDomain(raw)
	return err
}

// String returns the domain as a string.
func (d Domain) String() string { return d.raw }

// TLD returns the top-level domain.
func (d Domain) TLD() string {
	if len(d.labels) == 0 {
		return ""
	}
	return d.labels[len(d.labels)-1]
}

// Root returns the root domain (e.g., "example.com" from "sub.example.com").
func (d Domain) Root() string {
	if len(d.labels) < 2 {
		return d.raw
	}
	return strings.Join(d.labels[len(d.labels)-2:], ".")
}

// Labels returns all labels in the domain.
func (d Domain) Labels() []string {
	out := make([]string, len(d.labels))
	copy(out, d.labels)
	return out
}

// Depth returns the subdomain depth (0 for root domain).
func (d Domain) Depth() int {
	if len(d.labels) <= 2 {
		return 0
	}
	return len(d.labels) - 2
}

// IsSubdomainOf returns true if d is a subdomain of parent.
func (d Domain) IsSubdomainOf(parent Domain) bool {
	return strings.HasSuffix(d.raw, "."+parent.raw)
}

// IsWildcard checks if a raw string is a wildcard domain.
func IsWildcard(raw string) bool {
	return wildcardDomainRegex.MatchString(strings.TrimSpace(raw))
}

// IsSensitiveDomain checks if the domain belongs to a sensitive TLD (gov, mil, edu).
func (d Domain) IsSensitiveDomain() bool {
	sensitive := []string{".gov", ".mil", ".edu", ".gov.", ".mil.", ".edu."}
	for _, s := range sensitive {
		if strings.HasSuffix(d.raw, s) {
			return true
		}
	}
	return false
}

// ResolveIPs performs DNS lookup for the domain.
func (d Domain) ResolveIPs() ([]net.IP, error) {
	ips, err := net.LookupIP(d.raw)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", d.raw, err)
	}
	return ips, nil
}
