package types

import "time"

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the severity as a human-readable string.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to a Severity.
func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// FindingType categorizes the kind of finding.
type FindingType string

const (
	FindingSubdomain     FindingType = "subdomain"
	FindingWebEndpoint   FindingType = "web_endpoint"
	FindingPort          FindingType = "port"
	FindingVulnerability FindingType = "vulnerability"
	FindingSecret        FindingType = "secret"
	FindingMiscConfig    FindingType = "misconfig"
	FindingInfo          FindingType = "info"
)

// Finding represents a unified security finding or discovery.
type Finding struct {
	// Identity
	ID     string `json:"id"`
	ScanID string `json:"scan_id"`

	// Classification
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	Module   string      `json:"module"`
	Tool     string      `json:"tool"`

	// Target
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	URL    string `json:"url,omitempty"`
	Scheme string `json:"scheme,omitempty"`

	// Details
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Reference   string            `json:"reference,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// Raw tool output (for debugging / full context)
	RawOutput string `json:"raw_output,omitempty"`

	// HTTP Replay Data (for web findings)
	RequestRaw  string `json:"request_raw,omitempty"`
	ResponseRaw string `json:"response_raw,omitempty"`

	// Pentester notes
	Notes string `json:"notes,omitempty"`

	// Timestamps
	FoundAt   time.Time `json:"found_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// Dedup
	Fingerprint string `json:"fingerprint"`
}

// IsNew returns true if this finding is newer than the given timestamp.
func (f Finding) IsNew(since time.Time) bool {
	return f.FoundAt.After(since)
}

// HasTag checks if the finding has a specific tag.
func (f Finding) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// SeverityAtLeast returns true if the finding severity is >= minimum.
func (f Finding) SeverityAtLeast(min Severity) bool {
	return f.Severity >= min
}
