package storage

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const CurrentSchemaVersion = 22

var (
	ErrInvalidMigration          = errors.New("invalid storage migration")
	ErrPolicyScopeVersionExists  = errors.New("policy scope version already exists")
	ErrEvidenceObservationExists = errors.New("evidence observation already exists")
)

type DB struct {
	sql *sql.DB
}

func Open(path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("storage path is required")
	}
	if path != ":memory:" && (strings.HasPrefix(path, "file:") || strings.ContainsAny(path, "?#")) {
		return nil, errors.New("storage path must be a filesystem path, not a SQLite URI")
	}
	dsn := path
	if path == ":memory:" {
		dsn = "file:wraith-phase2?mode=memory&cache=shared&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	} else if !strings.HasPrefix(path, "file:") {
		dsn = "file:" + filepath.Clean(path) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	}
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	database.SetMaxOpenConns(8)
	database.SetMaxIdleConns(8)
	if err := database.Ping(); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &DB{sql: database}, nil
}

func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	return db.sql.Close()
}

func (db *DB) Migrate(ctx context.Context) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var applied int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("read migration version: %w", err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		version, name, err := parseMigrationName(entry.Name())
		if err != nil {
			return err
		}
		if version <= applied {
			continue
		}
		migration, err := migrationFS.ReadFile(filepath.Join("migrations", entry.Name()))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES(?, ?)`, version, name); err != nil {
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}
		applied = version
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func parseMigrationName(filename string) (int, string, error) {
	if filepath.Ext(filename) != ".sql" {
		return 0, "", fmt.Errorf("%w: %s must be a .sql file", ErrInvalidMigration, filename)
	}
	parts := strings.SplitN(strings.TrimSuffix(filename, ".sql"), "_", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("%w: %s must use NNN_name.sql", ErrInvalidMigration, filename)
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil || version < 1 {
		return 0, "", fmt.Errorf("%w: %s has invalid version", ErrInvalidMigration, filename)
	}
	return version, parts[1], nil
}

func (db *DB) SaveScan(ctx context.Context, scan ScanRecord, devices []DeviceRecord, subdomains []SubdomainRecord) (int64, error) {
	if db == nil || db.sql == nil {
		return 0, errors.New("storage database is not initialized")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin scan transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO scans(target, scan_type, started_at, completed_at) VALUES(?, ?, ?, ?)`, scan.Target, scan.ScanType, scan.StartedAt, scan.CompletedAt)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read scan id: %w", err)
	}
	for _, device := range devices {
		ports := device.OpenPortsJSON
		if ports == "" {
			ports = "[]"
		}
		firstSeen, lastSeen := device.FirstSeen, device.LastSeen
		if firstSeen == "" {
			firstSeen = scan.StartedAt
		}
		if lastSeen == "" {
			lastSeen = scan.CompletedAt
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices(scan_id, ip, mac, open_ports, os_guess, confidence, first_seen, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, scanID, device.IP, device.MAC, ports, device.OSGuess, device.Confidence, firstSeen, lastSeen); err != nil {
			return 0, fmt.Errorf("insert device: %w", err)
		}
	}
	for _, subdomain := range subdomains {
		firstSeen, lastSeen := subdomain.FirstSeen, subdomain.LastSeen
		if firstSeen == "" {
			firstSeen = scan.StartedAt
		}
		if lastSeen == "" {
			lastSeen = scan.CompletedAt
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO subdomains(scan_id, domain, subdomain, ip, status_code, title, server_header, tech_guess, first_seen, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, scanID, subdomain.Domain, subdomain.Subdomain, subdomain.IP, subdomain.StatusCode, subdomain.Title, subdomain.ServerHeader, subdomain.TechGuess, firstSeen, lastSeen); err != nil {
			return 0, fmt.Errorf("insert subdomain: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit scan: %w", err)
	}
	return scanID, nil
}

func (db *DB) LatestScans(ctx context.Context, target string, limit int) ([]ScanRecord, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if limit < 1 || limit > 2 {
		return nil, errors.New("history limit must be 1 or 2")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT id, target, scan_type, started_at, completed_at FROM scans WHERE target = ? ORDER BY completed_at DESC, id DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, fmt.Errorf("query latest scans: %w", err)
	}
	defer rows.Close()
	result := make([]ScanRecord, 0, limit)
	for rows.Next() {
		var scan ScanRecord
		if err := rows.Scan(&scan.ID, &scan.Target, &scan.ScanType, &scan.StartedAt, &scan.CompletedAt); err != nil {
			return nil, fmt.Errorf("scan latest scans: %w", err)
		}
		result = append(result, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate latest scans: %w", err)
	}
	return result, nil
}

func (db *DB) LoadSubdomainSnapshots(ctx context.Context, scanID int64) ([]SubdomainSnapshot, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT subdomain, ip, status_code, tech_guess FROM subdomains WHERE scan_id = ? ORDER BY subdomain`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query subdomain snapshots: %w", err)
	}
	defer rows.Close()
	result := make([]SubdomainSnapshot, 0)
	for rows.Next() {
		var snapshot SubdomainSnapshot
		if err := rows.Scan(&snapshot.Subdomain, &snapshot.IP, &snapshot.StatusCode, &snapshot.TechGuess); err != nil {
			return nil, fmt.Errorf("scan subdomain snapshots: %w", err)
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subdomain snapshots: %w", err)
	}
	return result, nil
}

func (db *DB) CurrentSchemaVersion(ctx context.Context) int {
	if db == nil || db.sql == nil {
		return 0
	}
	var version int
	if err := db.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0
	}
	return version
}

func (db *DB) SaveScanWithFindings(ctx context.Context, scan ScanRecord, devices []DeviceRecord, subdomains []SubdomainRecord, contentFindings []ContentFindingRecord, jsFindings []JSFindingRecord) (int64, error) {
	return db.SaveScanWithAllFindings(ctx, scan, devices, subdomains, contentFindings, jsFindings, nil, nil)
}

func (db *DB) SaveScanWithAllFindings(ctx context.Context, scan ScanRecord, devices []DeviceRecord, subdomains []SubdomainRecord, contentFindings []ContentFindingRecord, jsFindings []JSFindingRecord, portFindings []PortFindingRecord, vulnFindings []VulnFindingRecord) (int64, error) {
	if db == nil || db.sql == nil {
		return 0, errors.New("storage database is not initialized")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin scan transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO scans(target, scan_type, started_at, completed_at) VALUES(?, ?, ?, ?)`, scan.Target, scan.ScanType, scan.StartedAt, scan.CompletedAt)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read scan id: %w", err)
	}
	if err := insertDevicesAndSubdomains(ctx, tx, scanID, scan, devices, subdomains); err != nil {
		return 0, err
	}
	for index := range contentFindings {
		finding := &contentFindings[index]
		if finding.DiscoveredAt == "" {
			finding.DiscoveredAt = scan.CompletedAt
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO content_findings(scan_id, subdomain, path, status_code, response_length, discovered_at) VALUES(?, ?, ?, ?, ?, ?)`, scanID, finding.Subdomain, finding.Path, finding.StatusCode, finding.ResponseLength, finding.DiscoveredAt)
		if err != nil {
			return 0, fmt.Errorf("insert content finding: %w", err)
		}
		finding.ID, err = result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("read content finding id: %w", err)
		}
		finding.ScanID = scanID
	}
	for index := range jsFindings {
		finding := &jsFindings[index]
		if finding.DiscoveredAt == "" {
			finding.DiscoveredAt = scan.CompletedAt
		}
		if finding.FindingType == "secret" {
			if finding.Confidence != "potential" {
				return 0, errors.New("secret findings must use potential confidence")
			}
			if finding.Value != "REDACTED" && !strings.Contains(finding.Value, "…") {
				return 0, errors.New("secret findings must be redacted before persistence")
			}
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO js_findings(scan_id, subdomain, source_file, finding_type, value, confidence, discovered_at) VALUES(?, ?, ?, ?, ?, ?, ?)`, scanID, finding.Subdomain, finding.SourceFile, finding.FindingType, finding.Value, finding.Confidence, finding.DiscoveredAt)
		if err != nil {
			return 0, fmt.Errorf("insert JS finding: %w", err)
		}
		finding.ID, err = result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("read JS finding id: %w", err)
		}
		finding.ScanID = scanID
	}
	for index := range portFindings {
		finding := &portFindings[index]
		if finding.Source != "native" && finding.Source != "nmap" {
			return 0, fmt.Errorf("invalid port finding source %q", finding.Source)
		}
		if finding.DiscoveredAt == "" {
			finding.DiscoveredAt = scan.CompletedAt
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO port_findings(scan_id, subdomain_or_ip, port, protocol, service, banner, source, discovered_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, scanID, finding.SubdomainOrIP, finding.Port, finding.Protocol, finding.Service, finding.Banner, finding.Source, finding.DiscoveredAt)
		if err != nil {
			return 0, fmt.Errorf("insert port finding: %w", err)
		}
		finding.ID, err = result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("read port finding id: %w", err)
		}
		finding.ScanID = scanID
	}
	for index := range vulnFindings {
		finding := &vulnFindings[index]
		if finding.DiscoveredAt == "" {
			finding.DiscoveredAt = scan.CompletedAt
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO vuln_findings(scan_id, subdomain, template_id, severity, matched_url, description, discovered_at) VALUES(?, ?, ?, ?, ?, ?, ?)`, scanID, finding.Subdomain, finding.TemplateID, finding.Severity, finding.MatchedURL, finding.Description, finding.DiscoveredAt)
		if err != nil {
			return 0, fmt.Errorf("insert vulnerability finding: %w", err)
		}
		finding.ID, err = result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("read vulnerability finding id: %w", err)
		}
		finding.ScanID = scanID
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit scan: %w", err)
	}
	return scanID, nil
}

func insertDevicesAndSubdomains(ctx context.Context, tx *sql.Tx, scanID int64, scan ScanRecord, devices []DeviceRecord, subdomains []SubdomainRecord) error {
	for index := range devices {
		device := &devices[index]
		ports := device.OpenPortsJSON
		if ports == "" {
			ports = "[]"
		}
		firstSeen, lastSeen := device.FirstSeen, device.LastSeen
		if firstSeen == "" {
			firstSeen = scan.StartedAt
		}
		if lastSeen == "" {
			lastSeen = scan.CompletedAt
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO devices(scan_id, ip, mac, open_ports, os_guess, confidence, first_seen, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, scanID, device.IP, device.MAC, ports, device.OSGuess, device.Confidence, firstSeen, lastSeen)
		if err != nil {
			return fmt.Errorf("insert device: %w", err)
		}
		device.ID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read device id: %w", err)
		}
		device.ScanID = scanID
	}
	for index := range subdomains {
		subdomain := &subdomains[index]
		firstSeen, lastSeen := subdomain.FirstSeen, subdomain.LastSeen
		if firstSeen == "" {
			firstSeen = scan.StartedAt
		}
		if lastSeen == "" {
			lastSeen = scan.CompletedAt
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO subdomains(scan_id, domain, subdomain, ip, status_code, title, server_header, tech_guess, first_seen, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, scanID, subdomain.Domain, subdomain.Subdomain, subdomain.IP, subdomain.StatusCode, subdomain.Title, subdomain.ServerHeader, subdomain.TechGuess, firstSeen, lastSeen)
		if err != nil {
			return fmt.Errorf("insert subdomain: %w", err)
		}
		subdomain.ID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read subdomain id: %w", err)
		}
		subdomain.ScanID = scanID
	}
	return nil
}

func (db *DB) LoadContentFindings(ctx context.Context, scanID int64) ([]ContentFindingRecord, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, scan_id, subdomain, path, status_code, response_length, discovered_at FROM content_findings WHERE scan_id = ? ORDER BY subdomain, path`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query content findings: %w", err)
	}
	defer rows.Close()
	findings := make([]ContentFindingRecord, 0)
	for rows.Next() {
		var finding ContentFindingRecord
		if err := rows.Scan(&finding.ID, &finding.ScanID, &finding.Subdomain, &finding.Path, &finding.StatusCode, &finding.ResponseLength, &finding.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scan content finding: %w", err)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (db *DB) LoadJSFindings(ctx context.Context, scanID int64) ([]JSFindingRecord, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, scan_id, subdomain, source_file, finding_type, value, confidence, discovered_at FROM js_findings WHERE scan_id = ? ORDER BY subdomain, source_file, finding_type, value`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query JS findings: %w", err)
	}
	defer rows.Close()
	findings := make([]JSFindingRecord, 0)
	for rows.Next() {
		var finding JSFindingRecord
		if err := rows.Scan(&finding.ID, &finding.ScanID, &finding.Subdomain, &finding.SourceFile, &finding.FindingType, &finding.Value, &finding.Confidence, &finding.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scan JS finding: %w", err)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (db *DB) LoadPortFindings(ctx context.Context, scanID int64) ([]PortFindingRecord, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, scan_id, subdomain_or_ip, port, protocol, service, banner, source, discovered_at FROM port_findings WHERE scan_id = ? ORDER BY subdomain_or_ip, port, protocol, source`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query port findings: %w", err)
	}
	defer rows.Close()
	findings := make([]PortFindingRecord, 0)
	for rows.Next() {
		var finding PortFindingRecord
		if err := rows.Scan(&finding.ID, &finding.ScanID, &finding.SubdomainOrIP, &finding.Port, &finding.Protocol, &finding.Service, &finding.Banner, &finding.Source, &finding.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scan port finding: %w", err)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (db *DB) LoadVulnFindings(ctx context.Context, scanID int64) ([]VulnFindingRecord, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, scan_id, subdomain, template_id, severity, matched_url, description, discovered_at FROM vuln_findings WHERE scan_id = ? ORDER BY subdomain, template_id, matched_url`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query vulnerability findings: %w", err)
	}
	defer rows.Close()
	findings := make([]VulnFindingRecord, 0)
	for rows.Next() {
		var finding VulnFindingRecord
		if err := rows.Scan(&finding.ID, &finding.ScanID, &finding.Subdomain, &finding.TemplateID, &finding.Severity, &finding.MatchedURL, &finding.Description, &finding.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scan vulnerability finding: %w", err)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

// SaveProjectScope stores an immutable scope document and atomically makes it
// the active scope for its project. Reusing a version identifier is rejected;
// callers must create a new version to change policy.
func (db *DB) SaveProjectScope(ctx context.Context, scope policy.ProjectScope) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := policy.ValidateProjectScope(scope); err != nil {
		return fmt.Errorf("validate policy scope: %w", err)
	}
	actionsJSON, err := json.Marshal(scope.Authorization.ApprovedActions)
	if err != nil {
		return fmt.Errorf("marshal authorization actions: %w", err)
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy scope transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT version_id FROM project_scope_versions WHERE version_id = ?`, scope.VersionID).Scan(&existing)
	if err == nil {
		return ErrPolicyScopeVersionExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check policy scope version: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO project_scope_versions(version_id, project_id, authorization_id, authorization_owner_id, authorization_actions_json, authorization_expires_at, authorization_revoked_at, authorization_created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		scope.VersionID,
		scope.ProjectID,
		scope.Authorization.ID,
		scope.Authorization.OwnerID,
		string(actionsJSON),
		formatPolicyTime(scope.Authorization.ExpiresAt),
		formatPolicyTime(scope.Authorization.RevokedAt),
		formatRequiredPolicyTime(scope.Authorization.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("insert policy scope version: %w", err)
	}
	for _, rule := range scope.Rules {
		portsJSON, err := json.Marshal(rule.Ports)
		if err != nil {
			return fmt.Errorf("marshal policy rule ports: %w", err)
		}
		protocolsJSON, err := json.Marshal(rule.Protocols)
		if err != nil {
			return fmt.Errorf("marshal policy rule protocols: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO scope_rules(scope_version_id, id, project_id, effect, target_type, value, ports_json, protocols_json, expires_at, revoked_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scope.VersionID,
			rule.ID,
			rule.ProjectID,
			rule.Effect,
			rule.TargetType,
			rule.Value,
			string(portsJSON),
			string(protocolsJSON),
			formatPolicyTime(rule.ExpiresAt),
			formatPolicyTime(rule.RevokedAt),
			formatRequiredPolicyTime(rule.CreatedAt),
		)
		if err != nil {
			return fmt.Errorf("insert policy scope rule: %w", err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO active_project_scopes(project_id, scope_version_id, activated_at) VALUES(?, ?, ?) ON CONFLICT(project_id) DO UPDATE SET scope_version_id = excluded.scope_version_id, activated_at = excluded.activated_at`, scope.ProjectID, scope.VersionID, formatRequiredPolicyTime(scope.Authorization.CreatedAt))
	if err != nil {
		return fmt.Errorf("activate policy scope: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy scope: %w", err)
	}
	return nil
}

// LoadProjectScope returns the single active immutable scope version for the
// requested project. It has no cross-project fallback.
func (db *DB) LoadProjectScope(ctx context.Context, projectID string) (policy.ProjectScope, error) {
	if db == nil || db.sql == nil {
		return policy.ProjectScope{}, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" {
		return policy.ProjectScope{}, policy.ErrNoScope
	}
	var (
		scope                    policy.ProjectScope
		authorizationActionsJSON string
		authorizationExpiresAt   sql.NullString
		authorizationRevokedAt   sql.NullString
		authorizationCreatedAt   string
	)
	err := db.sql.QueryRowContext(ctx, `SELECT scope.version_id, scope.project_id, scope.authorization_id, scope.authorization_owner_id, scope.authorization_actions_json, scope.authorization_expires_at, scope.authorization_revoked_at, scope.authorization_created_at FROM active_project_scopes active JOIN project_scope_versions scope ON scope.version_id = active.scope_version_id WHERE active.project_id = ?`, projectID).Scan(
		&scope.VersionID,
		&scope.ProjectID,
		&scope.Authorization.ID,
		&scope.Authorization.OwnerID,
		&authorizationActionsJSON,
		&authorizationExpiresAt,
		&authorizationRevokedAt,
		&authorizationCreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.ProjectScope{}, policy.ErrNoScope
	}
	if err != nil {
		return policy.ProjectScope{}, fmt.Errorf("load active policy scope: %w", err)
	}
	scope.Authorization.ProjectID = scope.ProjectID
	scope.Authorization.ScopeVersionID = scope.VersionID
	if err := json.Unmarshal([]byte(authorizationActionsJSON), &scope.Authorization.ApprovedActions); err != nil {
		return policy.ProjectScope{}, fmt.Errorf("decode authorization actions: %w", err)
	}
	createdAt, err := parseRequiredPolicyTime(authorizationCreatedAt)
	if err != nil {
		return policy.ProjectScope{}, fmt.Errorf("decode authorization creation time: %w", err)
	}
	scope.Authorization.CreatedAt = createdAt
	if scope.Authorization.ExpiresAt, err = parseOptionalPolicyTime(authorizationExpiresAt); err != nil {
		return policy.ProjectScope{}, fmt.Errorf("decode authorization expiration: %w", err)
	}
	if scope.Authorization.RevokedAt, err = parseOptionalPolicyTime(authorizationRevokedAt); err != nil {
		return policy.ProjectScope{}, fmt.Errorf("decode authorization revocation: %w", err)
	}

	rows, err := db.sql.QueryContext(ctx, `SELECT id, project_id, effect, target_type, value, ports_json, protocols_json, expires_at, revoked_at, created_at FROM scope_rules WHERE scope_version_id = ? ORDER BY id`, scope.VersionID)
	if err != nil {
		return policy.ProjectScope{}, fmt.Errorf("load policy rules: %w", err)
	}
	defer rows.Close()
	scope.Rules = make([]policy.ScopeRule, 0)
	for rows.Next() {
		var (
			rule          policy.ScopeRule
			portsJSON     string
			protocolsJSON string
			expiresAt     sql.NullString
			revokedAt     sql.NullString
			created       string
		)
		if err := rows.Scan(&rule.ID, &rule.ProjectID, &rule.Effect, &rule.TargetType, &rule.Value, &portsJSON, &protocolsJSON, &expiresAt, &revokedAt, &created); err != nil {
			return policy.ProjectScope{}, fmt.Errorf("scan policy rule: %w", err)
		}
		if err := json.Unmarshal([]byte(portsJSON), &rule.Ports); err != nil {
			return policy.ProjectScope{}, fmt.Errorf("decode policy rule ports: %w", err)
		}
		if err := json.Unmarshal([]byte(protocolsJSON), &rule.Protocols); err != nil {
			return policy.ProjectScope{}, fmt.Errorf("decode policy rule protocols: %w", err)
		}
		var parseErr error
		if rule.CreatedAt, parseErr = parseRequiredPolicyTime(created); parseErr != nil {
			return policy.ProjectScope{}, fmt.Errorf("decode policy rule creation time: %w", parseErr)
		}
		if rule.ExpiresAt, parseErr = parseOptionalPolicyTime(expiresAt); parseErr != nil {
			return policy.ProjectScope{}, fmt.Errorf("decode policy rule expiration: %w", parseErr)
		}
		if rule.RevokedAt, parseErr = parseOptionalPolicyTime(revokedAt); parseErr != nil {
			return policy.ProjectScope{}, fmt.Errorf("decode policy rule revocation: %w", parseErr)
		}
		scope.Rules = append(scope.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return policy.ProjectScope{}, fmt.Errorf("iterate policy rules: %w", err)
	}
	if err := policy.ValidateProjectScope(scope); err != nil {
		return policy.ProjectScope{}, fmt.Errorf("validate loaded policy scope: %w", err)
	}
	return scope, nil
}

func formatPolicyTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatRequiredPolicyTime(*value)
}

func formatRequiredPolicyTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseOptionalPolicyTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseRequiredPolicyTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseRequiredPolicyTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

// UpsertWebAsset records one canonical project-local asset. Existing identity
// rows are intentionally not overwritten because the asset identity is stable.
func (db *DB) UpsertWebAsset(ctx context.Context, asset evidence.WebAsset) (evidence.WebAsset, error) {
	if db == nil || db.sql == nil {
		return evidence.WebAsset{}, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(asset.ProjectID) == "" || strings.TrimSpace(asset.Identity) == "" || strings.TrimSpace(asset.CanonicalURL) == "" || asset.CreatedAt.IsZero() {
		return evidence.WebAsset{}, evidence.ErrInvalidAsset
	}
	if asset.Kind != evidence.AssetKindURL && asset.Kind != evidence.AssetKindJavaScript {
		return evidence.WebAsset{}, evidence.ErrInvalidAsset
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO web_assets(project_id, kind, identity, canonical_url, created_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(project_id, identity) DO NOTHING`, asset.ProjectID, asset.Kind, asset.Identity, asset.CanonicalURL, formatRequiredPolicyTime(asset.CreatedAt))
	if err != nil {
		return evidence.WebAsset{}, fmt.Errorf("upsert web asset: %w", err)
	}
	return asset, nil
}

func (db *DB) UpsertEndpoint(ctx context.Context, endpoint evidence.Endpoint) (evidence.Endpoint, error) {
	if db == nil || db.sql == nil {
		return evidence.Endpoint{}, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(endpoint.ProjectID) == "" || strings.TrimSpace(endpoint.Identity) == "" || strings.TrimSpace(endpoint.Method) == "" || strings.TrimSpace(endpoint.URL) == "" || endpoint.CreatedAt.IsZero() {
		return evidence.Endpoint{}, evidence.ErrInvalidEndpoint
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO web_endpoints(project_id, identity, method, url, created_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(project_id, identity) DO NOTHING`, endpoint.ProjectID, endpoint.Identity, endpoint.Method, endpoint.URL, formatRequiredPolicyTime(endpoint.CreatedAt))
	if err != nil {
		return evidence.Endpoint{}, fmt.Errorf("upsert endpoint: %w", err)
	}
	return endpoint, nil
}

func (db *DB) UpsertParameter(ctx context.Context, parameter evidence.Parameter) (evidence.Parameter, error) {
	if db == nil || db.sql == nil {
		return evidence.Parameter{}, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(parameter.ProjectID) == "" || strings.TrimSpace(parameter.Identity) == "" || strings.TrimSpace(parameter.EndpointIdentity) == "" || strings.TrimSpace(parameter.Name) == "" || parameter.CreatedAt.IsZero() {
		return evidence.Parameter{}, evidence.ErrInvalidParameter
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO endpoint_parameters(project_id, identity, endpoint_identity, location, name, created_at) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, identity) DO NOTHING`, parameter.ProjectID, parameter.Identity, parameter.EndpointIdentity, parameter.Location, parameter.Name, formatRequiredPolicyTime(parameter.CreatedAt))
	if err != nil {
		return evidence.Parameter{}, fmt.Errorf("upsert endpoint parameter: %w", err)
	}
	return parameter, nil
}

// AppendObservation inserts immutable, typed evidence. Reusing an observation
// ID is refused rather than overwriting evidence or silently changing history.
func (db *DB) AppendObservation(ctx context.Context, observation evidence.Observation) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(observation.ID) == "" || strings.TrimSpace(observation.ProjectID) == "" || strings.TrimSpace(observation.SubjectIdentity) == "" || strings.TrimSpace(observation.Source) == "" || observation.ObservedAt.IsZero() || !json.Valid(observation.Payload) {
		return evidence.ErrInvalidEvidence
	}
	if len(observation.Payload) > 32<<10 {
		return evidence.ErrInvalidEvidence
	}
	result, err := db.sql.ExecContext(ctx, `INSERT INTO evidence_observations(id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, observation.ID, observation.ProjectID, observation.Kind, observation.SubjectIdentity, observation.Source, formatRequiredPolicyTime(observation.ObservedAt), string(observation.Payload), boolToInt(observation.Redacted))
	if err != nil {
		return fmt.Errorf("append evidence observation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read evidence observation insert result: %w", err)
	}
	if rows == 0 {
		return ErrEvidenceObservationExists
	}
	return nil
}

func (db *DB) ListWebAssets(ctx context.Context, projectID string) ([]evidence.WebAsset, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" {
		return nil, evidence.ErrInvalidAsset
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, kind, identity, canonical_url, created_at FROM web_assets WHERE project_id = ? ORDER BY identity`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list web assets: %w", err)
	}
	defer rows.Close()
	assets := make([]evidence.WebAsset, 0)
	for rows.Next() {
		var asset evidence.WebAsset
		var createdAt string
		if err := rows.Scan(&asset.ProjectID, &asset.Kind, &asset.Identity, &asset.CanonicalURL, &createdAt); err != nil {
			return nil, fmt.Errorf("scan web asset: %w", err)
		}
		parsed, err := parseRequiredPolicyTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("decode web asset creation time: %w", err)
		}
		asset.CreatedAt = parsed
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func (db *DB) ListEndpoints(ctx context.Context, projectID string) ([]evidence.Endpoint, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" {
		return nil, evidence.ErrInvalidEndpoint
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, identity, method, url, created_at FROM web_endpoints WHERE project_id = ? ORDER BY url, method, identity`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()
	endpoints := make([]evidence.Endpoint, 0)
	for rows.Next() {
		var endpoint evidence.Endpoint
		var createdAt string
		if err := rows.Scan(&endpoint.ProjectID, &endpoint.Identity, &endpoint.Method, &endpoint.URL, &createdAt); err != nil {
			return nil, fmt.Errorf("scan endpoint: %w", err)
		}
		parsed, err := parseRequiredPolicyTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("decode endpoint creation time: %w", err)
		}
		endpoint.CreatedAt = parsed
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

func (db *DB) ListParameters(ctx context.Context, projectID string) ([]evidence.Parameter, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" {
		return nil, evidence.ErrInvalidParameter
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, endpoint_identity, identity, location, name, created_at FROM endpoint_parameters WHERE project_id = ? ORDER BY endpoint_identity, identity`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list endpoint parameters: %w", err)
	}
	defer rows.Close()
	parameters := make([]evidence.Parameter, 0)
	for rows.Next() {
		var parameter evidence.Parameter
		var createdAt string
		if err := rows.Scan(&parameter.ProjectID, &parameter.EndpointIdentity, &parameter.Identity, &parameter.Location, &parameter.Name, &createdAt); err != nil {
			return nil, fmt.Errorf("scan endpoint parameter: %w", err)
		}
		parsed, err := parseRequiredPolicyTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("decode endpoint parameter creation time: %w", err)
		}
		parameter.CreatedAt = parsed
		parameters = append(parameters, parameter)
	}
	return parameters, rows.Err()
}

func (db *DB) ListObservations(ctx context.Context, projectID, subjectIdentity string) ([]evidence.Observation, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(subjectIdentity) == "" {
		return nil, evidence.ErrInvalidEvidence
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted FROM evidence_observations WHERE project_id = ? AND subject_identity = ? ORDER BY observed_at, id`, projectID, subjectIdentity)
	if err != nil {
		return nil, fmt.Errorf("list evidence observations: %w", err)
	}
	defer rows.Close()
	observations := make([]evidence.Observation, 0)
	for rows.Next() {
		var observation evidence.Observation
		var observedAt string
		var payload string
		var redacted int
		if err := rows.Scan(&observation.ID, &observation.ProjectID, &observation.Kind, &observation.SubjectIdentity, &observation.Source, &observedAt, &payload, &redacted); err != nil {
			return nil, fmt.Errorf("scan evidence observation: %w", err)
		}
		parsed, err := parseRequiredPolicyTime(observedAt)
		if err != nil {
			return nil, fmt.Errorf("decode evidence observation time: %w", err)
		}
		observation.ObservedAt = parsed
		observation.Payload = json.RawMessage(payload)
		observation.Redacted = redacted == 1
		observations = append(observations, observation)
	}
	return observations, rows.Err()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
