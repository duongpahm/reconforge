package models

import "time"

// Target represents a domain or IP being scanned.
type Target struct {
	ID          uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Name        string
	Description string
	Scans       []Scan
}

// Scan represents a reconnaissance scan execution.
type Scan struct {
	ID         uint
	CreatedAt  time.Time
	UpdatedAt  time.Time
	TargetID   uint
	Target     string
	TargetName string
	Mode       string
	Status     string
	Findings   int
	Duration   time.Duration
	WorkflowID string
	RunID      string
}
