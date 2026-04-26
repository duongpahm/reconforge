package project

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/reconforge/reconforge/internal/models"
)

// ScanDiff represents the difference between two scans.
type ScanDiff struct {
	BaseScan    *models.Scan
	CompareScan *models.Scan
	Added       []models.Finding
	Removed     []models.Finding
	Unchanged   []models.Finding
}

// GetScanByID retrieves a scan by its ID.
func (m *Manager) GetScanByID(runID string) (*models.Scan, error) {
	row := m.db.QueryRow(
		`SELECT id, created_at, updated_at, COALESCE(target_id, 0), COALESCE(target, ''), COALESCE(target_name, ''),
			COALESCE(mode, ''), COALESCE(status, ''), COALESCE(findings, 0), COALESCE(duration, 0),
			COALESCE(workflow_id, ''), run_id
		 FROM scans WHERE run_id = ?`,
		runID,
	)
	scan, err := scanScanRow(row)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan %s: %w", runID, err)
	}
	return scan, nil
}

// GetLastNScans retrieves the last N scans for a specific target.
func (m *Manager) GetLastNScans(target string, n int) ([]models.Scan, error) {
	query := `SELECT id, created_at, updated_at, COALESCE(target_id, 0), COALESCE(target, ''), COALESCE(target_name, ''),
		COALESCE(mode, ''), COALESCE(status, ''), COALESCE(findings, 0), COALESCE(duration, 0),
		COALESCE(workflow_id, ''), run_id
		FROM scans`
	var args []any
	if target != "" {
		query += ` WHERE target = ? OR target_name = ?`
		args = append(args, target, target)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, n)

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get last scans: %w", err)
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		scan, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

// DiffScans computes the difference in findings between baseScanID (older) and compareScanID (newer).
func (m *Manager) DiffScans(baseScanID, compareScanID string) (*ScanDiff, error) {
	baseScan, err := m.GetScanByID(baseScanID)
	if err != nil {
		return nil, err
	}

	compareScan, err := m.GetScanByID(compareScanID)
	if err != nil {
		return nil, err
	}

	baseFindings, err := m.findingsByScanID(baseScanID)
	if err != nil {
		return nil, err
	}
	compareFindings, err := m.findingsByScanID(compareScanID)
	if err != nil {
		return nil, err
	}

	baseMap := make(map[string]models.Finding)
	for _, finding := range baseFindings {
		baseMap[finding.Fingerprint] = finding
	}

	compareMap := make(map[string]models.Finding)
	for _, finding := range compareFindings {
		compareMap[finding.Fingerprint] = finding
	}

	var added, removed, unchanged []models.Finding
	for fingerprint, finding := range compareMap {
		if _, exists := baseMap[fingerprint]; exists {
			unchanged = append(unchanged, finding)
		} else {
			added = append(added, finding)
		}
	}
	for fingerprint, finding := range baseMap {
		if _, exists := compareMap[fingerprint]; !exists {
			removed = append(removed, finding)
		}
	}

	return &ScanDiff{
		BaseScan:    baseScan,
		CompareScan: compareScan,
		Added:       added,
		Removed:     removed,
		Unchanged:   unchanged,
	}, nil
}

func (m *Manager) findingsByScanID(scanID string) ([]models.Finding, error) {
	rows, err := m.db.Query(
		`SELECT id, finding_id, scan_id, target, COALESCE(type, ''), COALESCE(severity, ''), COALESCE(module, ''),
			COALESCE(tool, ''), COALESCE(host, ''), COALESCE(url, ''), COALESCE(title, ''), COALESCE(description, ''),
			COALESCE(evidence, ''), COALESCE(reference, ''), COALESCE(tags, ''), COALESCE(raw_output, ''),
			COALESCE(request_raw, ''), COALESCE(response_raw, ''), COALESCE(notes, ''), COALESCE(fingerprint, ''),
			created_at, updated_at
		 FROM findings WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func scanScan(scanner interface{ Scan(dest ...any) error }) (models.Scan, error) {
	var scan models.Scan
	var createdAt, updatedAt string
	var duration int64
	if err := scanner.Scan(
		&scan.ID, &createdAt, &updatedAt, &scan.TargetID, &scan.Target, &scan.TargetName,
		&scan.Mode, &scan.Status, &scan.Findings, &duration, &scan.WorkflowID, &scan.RunID,
	); err != nil {
		return models.Scan{}, err
	}
	scan.CreatedAt = parseDBTime(createdAt)
	scan.UpdatedAt = parseDBTime(updatedAt)
	scan.Duration = time.Duration(duration)
	return scan, nil
}

func scanScanRow(row *sql.Row) (*models.Scan, error) {
	scan, err := scanScan(row)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}
