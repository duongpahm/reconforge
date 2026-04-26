package project

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/duongpahm/ReconForge/internal/models"
	"github.com/duongpahm/ReconForge/internal/module"
)

// SaveFindings converts and persists an array of module.Finding to the database.
func (m *Manager) SaveFindings(scanID, target string, findings []module.Finding) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO scans (run_id, target, target_name, status, findings, created_at, updated_at)
		 VALUES (?, ?, ?, 'completed', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT(run_id) DO UPDATE SET
		   target = excluded.target,
		   target_name = excluded.target_name,
		   findings = excluded.findings,
		   status = excluded.status,
		   updated_at = CURRENT_TIMESTAMP`,
		scanID, target, target, len(findings),
	); err != nil {
		return err
	}

	for _, f := range findings {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(f.Module+f.Type+f.Target+f.Detail)))
		findingID := fmt.Sprintf("%x", sha256.Sum256([]byte(scanID+":"+fingerprint)))
		_, err := tx.Exec(
			`INSERT INTO findings (
				finding_id, scan_id, target, type, severity, module, host, url, title, description,
				request_raw, response_raw, fingerprint, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
			ON CONFLICT(finding_id) DO UPDATE SET
				request_raw = excluded.request_raw,
				response_raw = excluded.response_raw,
				updated_at = CURRENT_TIMESTAMP`,
			findingID, scanID, target, f.Type, f.Severity, f.Module, f.Host, f.URL, f.Target, f.Detail,
			f.RequestRaw, f.ResponseRaw, fingerprint,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListFindings queries the database for findings based on filters.
func (m *Manager) ListFindings(target string, severity string, tag string, module string, findingType string) ([]models.Finding, error) {
	query := `SELECT id, finding_id, scan_id, target, COALESCE(type, ''), COALESCE(severity, ''), COALESCE(module, ''),
		COALESCE(tool, ''), COALESCE(host, ''), COALESCE(url, ''), COALESCE(title, ''), COALESCE(description, ''),
		COALESCE(evidence, ''), COALESCE(reference, ''), COALESCE(tags, ''), COALESCE(raw_output, ''),
		COALESCE(request_raw, ''), COALESCE(response_raw, ''), COALESCE(notes, ''), COALESCE(fingerprint, ''),
		created_at, updated_at
		FROM findings WHERE 1=1`
	var args []any

	if target != "" {
		query += ` AND target = ?`
		args = append(args, target)
	}
	if severity != "" {
		sevs := splitCSV(severity)
		query += ` AND severity IN (` + placeholders(len(sevs)) + `)`
		for _, sev := range sevs {
			args = append(args, sev)
		}
	}
	if module != "" {
		query += ` AND module = ?`
		args = append(args, module)
	}
	if findingType != "" {
		query += ` AND type = ?`
		args = append(args, findingType)
	}
	if tag != "" {
		query += ` AND tags LIKE ?`
		args = append(args, `%`+tag+`%`)
	}
	query += ` ORDER BY created_at DESC, id DESC`

	rows, err := m.db.Query(query, args...)
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

// GetFinding retrieves a single finding by its finding_id.
func (m *Manager) GetFinding(findingID string) (*models.Finding, error) {
	row := m.db.QueryRow(
		`SELECT id, finding_id, scan_id, target, COALESCE(type, ''), COALESCE(severity, ''), COALESCE(module, ''),
			COALESCE(tool, ''), COALESCE(host, ''), COALESCE(url, ''), COALESCE(title, ''), COALESCE(description, ''),
			COALESCE(evidence, ''), COALESCE(reference, ''), COALESCE(tags, ''), COALESCE(raw_output, ''),
			COALESCE(request_raw, ''), COALESCE(response_raw, ''), COALESCE(notes, ''), COALESCE(fingerprint, ''),
			created_at, updated_at
		 FROM findings WHERE finding_id = ?`,
		findingID,
	)
	finding, err := scanFindingRow(row)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// UpdateFindingTag appends a tag to a finding.
func (m *Manager) UpdateFindingTag(findingID string, tag string, remove bool) error {
	finding, err := m.GetFinding(findingID)
	if err != nil {
		return err
	}

	var tags []string
	if finding.Tags != "" {
		_ = json.Unmarshal([]byte(finding.Tags), &tags)
	}

	updated := false
	var newTags []string
	for _, t := range tags {
		if t == tag {
			if remove {
				updated = true
				continue
			}
			return nil
		}
		newTags = append(newTags, t)
	}

	if !remove {
		newTags = append(newTags, tag)
		updated = true
	}
	if !updated {
		return nil
	}

	tagsJSON, _ := json.Marshal(newTags)
	_, err = m.db.Exec(
		`UPDATE findings SET tags = ?, updated_at = CURRENT_TIMESTAMP WHERE finding_id = ?`,
		string(tagsJSON), findingID,
	)
	return err
}

// UpdateFindingNote sets the notes field for a finding.
func (m *Manager) UpdateFindingNote(findingID string, note string) error {
	_, err := m.db.Exec(
		`UPDATE findings SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE finding_id = ?`,
		note, findingID,
	)
	return err
}

// DedupFindings marks duplicate findings by fingerprint, keeping the earliest one.
func (m *Manager) DedupFindings(target string, write bool) (int, error) {
	rows, err := m.db.Query(
		`SELECT fingerprint
		 FROM findings
		 WHERE target = ? AND fingerprint != ''
		 GROUP BY fingerprint
		 HAVING COUNT(*) > 1`,
		target,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var duplicateFingerprints []string
	for rows.Next() {
		var fingerprint string
		if err := rows.Scan(&fingerprint); err != nil {
			return 0, err
		}
		duplicateFingerprints = append(duplicateFingerprints, fingerprint)
	}

	count := 0
	for _, fp := range duplicateFingerprints {
		findings, err := m.findingsByFingerprint(target, fp)
		if err != nil {
			return count, err
		}
		for i := 1; i < len(findings); i++ {
			count++
			if write {
				if err := m.UpdateFindingTag(findings[i].FindingID, "duplicate", false); err != nil {
					return count, err
				}
			}
		}
	}

	return count, nil
}

func (m *Manager) findingsByFingerprint(target, fingerprint string) ([]models.Finding, error) {
	rows, err := m.db.Query(
		`SELECT id, finding_id, scan_id, target, COALESCE(type, ''), COALESCE(severity, ''), COALESCE(module, ''),
			COALESCE(tool, ''), COALESCE(host, ''), COALESCE(url, ''), COALESCE(title, ''), COALESCE(description, ''),
			COALESCE(evidence, ''), COALESCE(reference, ''), COALESCE(tags, ''), COALESCE(raw_output, ''),
			COALESCE(request_raw, ''), COALESCE(response_raw, ''), COALESCE(notes, ''), COALESCE(fingerprint, ''),
			created_at, updated_at
		 FROM findings
		 WHERE target = ? AND fingerprint = ?
		 ORDER BY id ASC`,
		target, fingerprint,
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

func scanFinding(scanner interface{ Scan(dest ...any) error }) (models.Finding, error) {
	var finding models.Finding
	var createdAt, updatedAt string
	if err := scanner.Scan(
		&finding.ID, &finding.FindingID, &finding.ScanID, &finding.Target, &finding.Type, &finding.Severity,
		&finding.Module, &finding.Tool, &finding.Host, &finding.URL, &finding.Title, &finding.Description,
		&finding.Evidence, &finding.Reference, &finding.Tags, &finding.RawOutput, &finding.RequestRaw,
		&finding.ResponseRaw, &finding.Notes, &finding.Fingerprint, &createdAt, &updatedAt,
	); err != nil {
		return models.Finding{}, err
	}
	finding.CreatedAt = parseDBTime(createdAt)
	finding.UpdatedAt = parseDBTime(updatedAt)
	return finding, nil
}

func scanFindingRow(row *sql.Row) (*models.Finding, error) {
	finding, err := scanFinding(row)
	if err != nil {
		return nil, err
	}
	return &finding, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func splitCSV(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
