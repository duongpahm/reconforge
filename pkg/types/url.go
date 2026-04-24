package types

import (
	"fmt"
	"net/url"
	"strings"
)

// URL represents a validated URL.
type URL struct {
	raw    string
	parsed *url.URL
}

// NewURL creates a validated URL from a raw string.
func NewURL(raw string) (URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URL{}, fmt.Errorf("URL cannot be empty")
	}

	// Add scheme if missing for parsing
	normalized := raw
	if !strings.Contains(normalized, "://") {
		normalized = "https://" + normalized
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL %q: %w", raw, err)
	}

	if parsed.Host == "" {
		return URL{}, fmt.Errorf("URL has no host: %q", raw)
	}

	// Validate the scheme
	switch parsed.Scheme {
	case "http", "https":
		// valid
	default:
		return URL{}, fmt.Errorf("unsupported scheme %q in URL %q", parsed.Scheme, raw)
	}

	return URL{raw: normalized, parsed: parsed}, nil
}

// String returns the URL as a string.
func (u URL) String() string { return u.raw }

// Host returns the hostname (without port).
func (u URL) Host() string { return u.parsed.Hostname() }

// Port returns the port or empty string.
func (u URL) Port() string { return u.parsed.Port() }

// Scheme returns the URL scheme (http or https).
func (u URL) Scheme() string { return u.parsed.Scheme }

// Path returns the URL path.
func (u URL) Path() string { return u.parsed.Path }

// Query returns the raw query string.
func (u URL) Query() string { return u.parsed.RawQuery }

// IsHTTPS returns true if the URL uses HTTPS.
func (u URL) IsHTTPS() bool { return u.parsed.Scheme == "https" }

// Domain attempts to extract a valid Domain from the URL host.
func (u URL) Domain() (Domain, error) {
	return NewDomain(u.parsed.Hostname())
}

// BaseURL returns scheme + host (no path/query).
func (u URL) BaseURL() string {
	return fmt.Sprintf("%s://%s", u.parsed.Scheme, u.parsed.Host)
}
