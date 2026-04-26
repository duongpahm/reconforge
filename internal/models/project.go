package models

import "time"

// Project represents a security engagement or testing project.
type Project struct {
	ID        uint
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      string
	Status    string
	ScopePath string
	Targets   []ProjectTarget
}

// ProjectTarget represents an individual target inside a project.
type ProjectTarget struct {
	ID          uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ProjectID   uint
	Target      string
	Description string
	Tags        string
}

// Finding represents a persistent security finding.
type Finding struct {
	ID          uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
	FindingID   string
	ScanID      string
	Target      string
	Type        string
	Severity    string
	Module      string
	Tool        string
	Host        string
	URL         string
	Title       string
	Description string
	Evidence    string
	Reference   string
	Tags        string
	RawOutput   string
	RequestRaw  string
	ResponseRaw string
	Notes       string
	Fingerprint string
}
