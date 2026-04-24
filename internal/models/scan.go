package models

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/driver/sqlite"
)

// Target represents a domain or IP being scanned.
type Target struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex"`
	Description string
	Scans       []Scan
}

// Scan represents a reconnaissance scan execution.
type Scan struct {
	gorm.Model
	TargetID    uint
	TargetName  string // Denormalized for fast query
	Mode        string
	Status      string // pending, running, completed, failed
	Findings    int
	Duration    time.Duration
	WorkflowID  string `gorm:"index"`
	RunID       string
}

// SetupDatabase initializes the SQLite connection and runs migrations.
func SetupDatabase(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Run auto migrations
	err = db.AutoMigrate(&Target{}, &Scan{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
