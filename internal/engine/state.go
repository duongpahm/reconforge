// Package engine provides the scan engine, state management, and pipeline orchestration.
package engine

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ScanStatus represents the current status of a scan.
type ScanStatus string

const (
	StatusPending  ScanStatus = "pending"
	StatusRunning  ScanStatus = "running"
	StatusComplete ScanStatus = "complete"
	StatusFailed   ScanStatus = "failed"
	StatusAborted  ScanStatus = "aborted"
)

// ScanState holds the state of a scan.
type ScanState struct {
	ID          string     `json:"id"`
	Target      string     `json:"target"`
	Mode        string     `json:"mode"`
	Status      ScanStatus `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Findings    int        `json:"findings"`
	Modules     []ModuleState `json:"modules,omitempty"`
}

// ModuleState tracks the state of a single module within a scan.
type ModuleState struct {
	Name      string     `json:"name"`
	Status    ScanStatus `json:"status"`
	Findings  int        `json:"findings"`
	StartedAt time.Time  `json:"started_at"`
	Duration  float64    `json:"duration_secs"`
	Error     string     `json:"error,omitempty"`
}

// StateManager manages scan state persistence via SQLite.
type StateManager struct {
	db *sql.DB
}

// NewStateManager creates a new state manager with the given SQLite database path.
func NewStateManager(dbPath string) (*StateManager, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}

	sm := &StateManager{db: db}
	if err := sm.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate state db: %w", err)
	}

	return sm, nil
}

func (sm *StateManager) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			mode TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			started_at DATETIME NOT NULL,
			completed_at DATETIME,
			findings INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS modules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT NOT NULL REFERENCES scans(id),
			name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			findings INTEGER DEFAULT 0,
			started_at DATETIME,
			duration_secs REAL DEFAULT 0,
			error TEXT,
			UNIQUE(scan_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS checkpoints (
			scan_id TEXT PRIMARY KEY REFERENCES scans(id),
			data BLOB NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)`,
		`CREATE INDEX IF NOT EXISTS idx_modules_scan ON modules(scan_id)`,
	}

	for _, m := range migrations {
		if _, err := sm.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	return nil
}

// StartScan creates a new scan record.
func (sm *StateManager) StartScan(target, mode string) (string, error) {
	id := fmt.Sprintf("%s-%d", target, time.Now().UnixNano())
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	_, err := sm.db.Exec(
		`INSERT INTO scans (id, target, mode, status, started_at) VALUES (?, ?, ?, ?, ?)`,
		id, target, mode, StatusRunning, now,
	)
	if err != nil {
		return "", fmt.Errorf("start scan: %w", err)
	}

	return id, nil
}

// parseTimeStr parses a SQLite datetime string into time.Time.
func parseTimeStr(s string) time.Time {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return t
	}
	return time.Time{}
}

// UpdateModule updates the state of a module within a scan.
func (sm *StateManager) UpdateModule(scanID, module string, status ScanStatus, findings int, duration float64, errMsg string) error {
	_, err := sm.db.Exec(
		`INSERT INTO modules (scan_id, name, status, findings, started_at, duration_secs, error)
		 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
		 ON CONFLICT(scan_id, name) DO UPDATE SET
		   status = excluded.status,
		   findings = excluded.findings,
		   duration_secs = excluded.duration_secs,
		   error = excluded.error`,
		scanID, module, status, findings, duration, errMsg,
	)
	if err != nil {
		return fmt.Errorf("update module %q: %w", module, err)
	}

	return nil
}

// MarkComplete marks a scan as complete.
func (sm *StateManager) MarkComplete(scanID string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	// Sum all findings from modules
	_, err := sm.db.Exec(
		`UPDATE scans SET
		   status = ?,
		   completed_at = ?,
		   findings = (SELECT COALESCE(SUM(findings), 0) FROM modules WHERE scan_id = ?)
		 WHERE id = ?`,
		StatusComplete, now, scanID, scanID,
	)
	if err != nil {
		return fmt.Errorf("mark complete: %w", err)
	}
	return nil
}

// MarkFailed marks a scan as failed.
func (sm *StateManager) MarkFailed(scanID string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err := sm.db.Exec(
		`UPDATE scans SET status = ?, completed_at = ? WHERE id = ?`,
		StatusFailed, now, scanID,
	)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

// GetScanState retrieves the full state of a scan.
func (sm *StateManager) GetScanState(scanID string) (*ScanState, error) {
	var state ScanState
	var startedAtStr string
	var completedAtStr sql.NullString

	err := sm.db.QueryRow(
		`SELECT id, target, mode, status, started_at, completed_at, findings FROM scans WHERE id = ?`,
		scanID,
	).Scan(&state.ID, &state.Target, &state.Mode, &state.Status, &startedAtStr, &completedAtStr, &state.Findings)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan %q not found", scanID)
		}
		return nil, fmt.Errorf("get scan state: %w", err)
	}

	// Parse time strings from SQLite
	state.StartedAt = parseTimeStr(startedAtStr)
	if completedAtStr.Valid && completedAtStr.String != "" {
		t := parseTimeStr(completedAtStr.String)
		state.CompletedAt = &t
	}

	// Load module states
	rows, err := sm.db.Query(
		`SELECT name, status, findings, COALESCE(started_at, CURRENT_TIMESTAMP), duration_secs, COALESCE(error, '') FROM modules WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("get modules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ms ModuleState
		var startedAtStr string
		if err := rows.Scan(&ms.Name, &ms.Status, &ms.Findings, &startedAtStr, &ms.Duration, &ms.Error); err != nil {
			return nil, fmt.Errorf("scan module row: %w", err)
		}
		// SQLite returns datetime as string; parse it
		if startedAtStr != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", startedAtStr); err == nil {
				ms.StartedAt = t
			} else if t, err := time.Parse(time.RFC3339, startedAtStr); err == nil {
				ms.StartedAt = t
			}
		}
		state.Modules = append(state.Modules, ms)
	}

	return &state, nil
}

// GetLastScan retrieves the most recent scan for a target.
func (sm *StateManager) GetLastScan(target string) (*ScanState, error) {
	var scanID string
	err := sm.db.QueryRow(
		`SELECT id FROM scans WHERE target = ? ORDER BY rowid DESC LIMIT 1`,
		target,
	).Scan(&scanID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // no previous scan
		}
		return nil, fmt.Errorf("get last scan: %w", err)
	}

	return sm.GetScanState(scanID)
}

// SaveCheckpoint saves checkpoint data for resuming a scan.
func (sm *StateManager) SaveCheckpoint(scanID string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	_, err = sm.db.Exec(
		`INSERT INTO checkpoints (scan_id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(scan_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`,
		scanID, jsonData,
	)
	if err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
}

// LoadCheckpoint loads checkpoint data for resuming a scan.
func (sm *StateManager) LoadCheckpoint(scanID string, dest interface{}) error {
	var data []byte
	err := sm.db.QueryRow(
		`SELECT data FROM checkpoints WHERE scan_id = ?`,
		scanID,
	).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("no checkpoint for scan %q", scanID)
		}
		return fmt.Errorf("load checkpoint: %w", err)
	}

	return json.Unmarshal(data, dest)
}

// Close closes the database connection.
func (sm *StateManager) Close() error {
	return sm.db.Close()
}
