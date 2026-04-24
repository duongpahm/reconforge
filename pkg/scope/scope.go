// Package scope provides in/out scope management and filtering.
package scope

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/reconforge/reconforge/pkg/types"
)

// Scope manages target scope definitions.
type Scope struct {
	InScope    []string // domains, CIDRs, wildcard patterns
	OutOfScope []string // exclusions
}

// NewScope creates a scope from in-scope and out-of-scope file paths.
func NewScope(inScopeFile, outOfScopeFile string) (*Scope, error) {
	s := &Scope{}

	if inScopeFile != "" {
		entries, err := readLines(inScopeFile)
		if err != nil {
			return nil, fmt.Errorf("read in-scope file: %w", err)
		}
		s.InScope = entries
	}

	if outOfScopeFile != "" {
		entries, err := readLines(outOfScopeFile)
		if err != nil {
			return nil, fmt.Errorf("read out-of-scope file: %w", err)
		}
		s.OutOfScope = entries
	}

	return s, nil
}

// IsInScope checks if a domain is within scope.
func (s *Scope) IsInScope(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// If no scope defined, everything is in scope
	if len(s.InScope) == 0 && len(s.OutOfScope) == 0 {
		return true
	}

	// Check out-of-scope first (deny takes precedence)
	for _, pattern := range s.OutOfScope {
		if matchesPattern(domain, pattern) {
			return false
		}
	}

	// If in-scope list is empty, allow everything not excluded
	if len(s.InScope) == 0 {
		return true
	}

	// Check in-scope
	for _, pattern := range s.InScope {
		if matchesPattern(domain, pattern) {
			return true
		}
	}

	return false
}

// CheckSensitive returns true if the domain is a sensitive TLD.
func CheckSensitive(domain string) bool {
	d, err := types.NewDomain(domain)
	if err != nil {
		return false
	}
	return d.IsSensitiveDomain()
}

// matchesPattern checks if a domain matches a scope pattern.
// Supports: exact match, wildcard (*.example.com), suffix (.example.com).
func matchesPattern(domain, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(domain)

	if pattern == domain {
		return true
	}

	// Wildcard: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix)
	}

	// Suffix: .example.com matches sub.example.com and example.com
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(domain, pattern) || domain == pattern[1:]
	}

	// Root domain match: example.com matches sub.example.com
	return strings.HasSuffix(domain, "."+pattern)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}
