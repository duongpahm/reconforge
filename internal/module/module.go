// Package module provides the module interface, registry, and scan context.
package module

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/duongpahm/ReconForge/internal/cache"
	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/ratelimit"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// Module is the interface that all reconnaissance modules must implement.
type Module interface {
	// Name returns the unique module identifier.
	Name() string

	// Description returns a human-readable description.
	Description() string

	// Phase returns which scan phase this module belongs to.
	Phase() engine.Phase

	// Dependencies returns names of modules that must run before this one.
	Dependencies() []string

	// RequiredTools returns the tool binaries this module needs.
	RequiredTools() []string

	// Run executes the module logic.
	Run(ctx context.Context, scan *ScanContext) error

	// Validate checks if the module can run with the given config.
	Validate(cfg *config.Config) error
}

// ScanContext provides shared resources to modules during execution.
type ScanContext struct {
	Target      string
	Config      *config.Config
	State       *engine.StateManager
	Runner      runner.ToolRunner
	SSHRunner   *runner.SSHRunner  // nil if no VM
	RateLimiter *ratelimit.AdaptiveLimiter
	Cache       *cache.FileCache
	Logger      zerolog.Logger
	OutputDir   string

	// Results from previous modules (shared mutable state)
	Results *ScanResults
}

// ScanResults holds shared results that modules can read/write.
// All mutating methods are thread-safe.
type ScanResults struct {
	mu         sync.RWMutex
	Subdomains []string
	LiveHosts  []string
	URLs       []string
	Emails     []string
	Findings   []Finding
}

// NewScanResults creates a new empty ScanResults.
func NewScanResults() *ScanResults {
	return &ScanResults{}
}

// AddSubdomains appends subdomains in a thread-safe manner, deduplicating.
func (sr *ScanResults) AddSubdomains(subs []string) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	existing := make(map[string]bool, len(sr.Subdomains))
	for _, s := range sr.Subdomains {
		existing[s] = true
	}

	added := 0
	for _, s := range subs {
		if s != "" && !existing[s] {
			sr.Subdomains = append(sr.Subdomains, s)
			existing[s] = true
			added++
		}
	}
	return added
}

// AddFindings appends findings in a thread-safe manner.
func (sr *ScanResults) AddFindings(findings []Finding) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.Findings = append(sr.Findings, findings...)
}

// GetFindings returns a snapshot of current findings.
func (sr *ScanResults) GetFindings() []Finding {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make([]Finding, len(sr.Findings))
	copy(out, sr.Findings)
	return out
}

// GetSubdomains returns a snapshot of current subdomains.
func (sr *ScanResults) GetSubdomains() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make([]string, len(sr.Subdomains))
	copy(out, sr.Subdomains)
	return out
}

// SubdomainCount returns the current subdomain count.
func (sr *ScanResults) SubdomainCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(sr.Subdomains)
}

// AddLiveHosts appends live hosts in a thread-safe manner, deduplicating.
func (sr *ScanResults) AddLiveHosts(hosts []string) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	existing := make(map[string]bool, len(sr.LiveHosts))
	for _, h := range sr.LiveHosts {
		existing[h] = true
	}

	added := 0
	for _, h := range hosts {
		if h != "" && !existing[h] {
			sr.LiveHosts = append(sr.LiveHosts, h)
			existing[h] = true
			added++
		}
	}
	return added
}

// GetLiveHosts returns a snapshot of current live hosts.
func (sr *ScanResults) GetLiveHosts() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make([]string, len(sr.LiveHosts))
	copy(out, sr.LiveHosts)
	return out
}

// AddURLs appends URLs in a thread-safe manner, deduplicating.
func (sr *ScanResults) AddURLs(urls []string) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	existing := make(map[string]bool, len(sr.URLs))
	for _, u := range sr.URLs {
		existing[u] = true
	}

	added := 0
	for _, u := range urls {
		if u != "" && !existing[u] {
			sr.URLs = append(sr.URLs, u)
			existing[u] = true
			added++
		}
	}
	return added
}

// GetURLs returns a snapshot of current URLs.
func (sr *ScanResults) GetURLs() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make([]string, len(sr.URLs))
	copy(out, sr.URLs)
	return out
}

// AddEmails appends emails in a thread-safe manner, deduplicating.
func (sr *ScanResults) AddEmails(emails []string) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	existing := make(map[string]bool, len(sr.Emails))
	for _, e := range sr.Emails {
		existing[e] = true
	}

	added := 0
	for _, e := range emails {
		if e != "" && !existing[e] {
			sr.Emails = append(sr.Emails, e)
			existing[e] = true
			added++
		}
	}
	return added
}

// GetEmails returns a snapshot of current emails.
func (sr *ScanResults) GetEmails() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make([]string, len(sr.Emails))
	copy(out, sr.Emails)
	return out
}

// Finding represents a discovered security issue.
type Finding struct {
	Module   string `json:"module"`
	Type     string `json:"type"`     // subdomain, url, vuln, info
	Severity string `json:"severity"` // info, low, medium, high, critical
	Target   string `json:"target"`
	Host     string `json:"host,omitempty"`
	URL      string `json:"url,omitempty"`
	Detail   string `json:"detail"`
	RequestRaw  string `json:"request_raw,omitempty"`
	ResponseRaw string `json:"response_raw,omitempty"`
}
