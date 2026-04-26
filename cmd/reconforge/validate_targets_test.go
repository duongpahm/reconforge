package main

import (
	"strings"
	"testing"
)

func TestValidateTargets(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		wantErr bool
		errSub  string
	}{
		{"valid_domain", []string{"example.com"}, false, ""},
		{"valid_subdomain", []string{"sub.example.com"}, false, ""},
		{"valid_ipv4", []string{"192.168.1.1"}, false, ""},
		{"valid_ipv6", []string{"2001:db8::1"}, false, ""},
		{"valid_cidr_v4", []string{"10.0.0.0/24"}, false, ""},
		{"valid_cidr_v6", []string{"2001:db8::/64"}, false, ""},
		{"valid_wildcard", []string{"*.example.com"}, false, ""},
		{"valid_multiple", []string{"example.com", "10.0.0.0/24", "*.acme.com"}, false, ""},

		{"empty", []string{""}, true, ""},
		{"whitespace_only", []string{"   "}, true, ""},
		{"invalid_ip_octets", []string{"999.999.999.999"}, true, ""},
		{"invalid_cidr_range", []string{"10.0.0.0/99"}, true, ""},
		{"invalid_cidr_addr", []string{"999.0.0.0/24"}, true, ""},
		{"domain_with_space", []string{"exam ple.com"}, true, ""},
		{"domain_no_tld", []string{"localhost"}, true, ""},
		{"wildcard_invalid_parent", []string{"*.no spaces.com"}, true, "wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargets(tt.targets)
			gotErr := err != nil

			if gotErr != tt.wantErr {
				t.Errorf("validateTargets(%v) error = %v, wantErr %v", tt.targets, err, tt.wantErr)
				return
			}

			if tt.errSub != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSub)
				}
			}
		})
	}
}
