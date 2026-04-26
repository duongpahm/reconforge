package project

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/models"
	_ "modernc.org/sqlite"
)

// Manager handles project-related database operations.
type Manager struct {
	db *sql.DB
}

// NewManager initializes the SQLite database for projects and returns a Manager.
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not get home dir: %w", err)
	}

	configDir := filepath.Join(home, ".reconforge")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return nil, fmt.Errorf("could not create config dir: %w", err)
	}

	dbPath := filepath.Join(configDir, "projects.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open project database: %w", err)
	}

	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	mgr := &Manager{db: db}
	if err := mgr.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate project database: %w", err)
	}

	return mgr, nil
}

func (m *Manager) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS projects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'active',
			scope_path TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS project_targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id INTEGER NOT NULL,
			target TEXT NOT NULL,
			description TEXT,
			tags TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(project_id, target)
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target_id INTEGER DEFAULT 0,
			target TEXT,
			target_name TEXT,
			mode TEXT,
			status TEXT,
			findings INTEGER DEFAULT 0,
			duration INTEGER DEFAULT 0,
			workflow_id TEXT,
			run_id TEXT NOT NULL UNIQUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			finding_id TEXT NOT NULL UNIQUE,
			scan_id TEXT,
			target TEXT NOT NULL,
			type TEXT,
			severity TEXT,
			module TEXT,
			tool TEXT,
			host TEXT,
			url TEXT,
			title TEXT,
			description TEXT,
			evidence TEXT,
			reference TEXT,
			tags TEXT,
			raw_output TEXT,
			request_raw TEXT,
			response_raw TEXT,
			notes TEXT,
			fingerprint TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name)`,
		`CREATE INDEX IF NOT EXISTS idx_project_targets_target ON project_targets(target)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_target_name ON scans(target_name)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_run_id ON scans(run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)`,
	}

	for _, stmt := range migrations {
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

// CreateProject creates a new project with the given name and scope file path.
func (m *Manager) CreateProject(name, scopePath string) error {
	_, err := m.db.Exec(
		`INSERT INTO projects (name, status, scope_path, created_at, updated_at)
		 VALUES (?, 'active', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		name, scopePath,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("project already exists")
		}
		return err
	}
	return nil
}

// AddTarget adds a target to an existing project.
func (m *Manager) AddTarget(projectName, target string) error {
	proj, err := m.GetProject(projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	_, err = m.db.Exec(
		`INSERT INTO project_targets (project_id, target, created_at, updated_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		proj.ID, target,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("target already exists in project")
		}
		return err
	}
	return nil
}

// ListProjects returns all projects.
func (m *Manager) ListProjects() ([]models.Project, error) {
	rows, err := m.db.Query(
		`SELECT id, name, status, COALESCE(scope_path, ''), created_at, updated_at
		 FROM projects
		 ORDER BY name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}

	return projects, rows.Err()
}

// ListTargetNames returns matching target names for shell completion.
func (m *Manager) ListTargetNames(prefix string) ([]string, error) {
	query := `SELECT DISTINCT target FROM project_targets`
	var args []any
	if prefix != "" {
		query += ` WHERE target LIKE ?`
		args = append(args, prefix+"%")
	}
	query += ` ORDER BY target ASC`

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, err
		}
		target = strings.TrimSpace(target)
		if target != "" {
			targets = append(targets, target)
		}
	}

	return targets, rows.Err()
}

// GetProject returns a project by name, including its targets.
func (m *Manager) GetProject(name string) (*models.Project, error) {
	row := m.db.QueryRow(
		`SELECT id, name, status, COALESCE(scope_path, ''), created_at, updated_at
		 FROM projects WHERE name = ?`,
		name,
	)
	project, err := scanProjectRow(row)
	if err != nil {
		return nil, err
	}

	targetRows, err := m.db.Query(
		`SELECT id, project_id, target, COALESCE(description, ''), COALESCE(tags, ''), created_at, updated_at
		 FROM project_targets
		 WHERE project_id = ?
		 ORDER BY target ASC`,
		project.ID,
	)
	if err != nil {
		return nil, err
	}
	defer targetRows.Close()

	for targetRows.Next() {
		target, err := scanProjectTarget(targetRows)
		if err != nil {
			return nil, err
		}
		project.Targets = append(project.Targets, target)
	}

	return project, targetRows.Err()
}

// ArchiveProject marks a project as archived.
func (m *Manager) ArchiveProject(name string) error {
	res, err := m.db.Exec(
		`UPDATE projects SET status = 'archived', updated_at = CURRENT_TIMESTAMP WHERE name = ?`,
		name,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("project not found")
	}
	return nil
}

// Close closes the database connection.
func (m *Manager) Close() error {
	return m.db.Close()
}

func parseDBTime(value string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		time.RFC3339,
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func scanProject(scanner interface{ Scan(dest ...any) error }) (models.Project, error) {
	var project models.Project
	var createdAt, updatedAt string
	if err := scanner.Scan(&project.ID, &project.Name, &project.Status, &project.ScopePath, &createdAt, &updatedAt); err != nil {
		return models.Project{}, err
	}
	project.CreatedAt = parseDBTime(createdAt)
	project.UpdatedAt = parseDBTime(updatedAt)
	return project, nil
}

func scanProjectRow(row *sql.Row) (*models.Project, error) {
	project, err := scanProject(row)
	if err != nil {
		return nil, err
	}
	return &project, nil
}

func scanProjectTarget(scanner interface{ Scan(dest ...any) error }) (models.ProjectTarget, error) {
	var target models.ProjectTarget
	var createdAt, updatedAt string
	if err := scanner.Scan(&target.ID, &target.ProjectID, &target.Target, &target.Description, &target.Tags, &createdAt, &updatedAt); err != nil {
		return models.ProjectTarget{}, err
	}
	target.CreatedAt = parseDBTime(createdAt)
	target.UpdatedAt = parseDBTime(updatedAt)
	return target, nil
}
