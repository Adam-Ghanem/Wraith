package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/scope"
)

func (db *DB) SaveScopeVersion(ctx context.Context, version scope.Version) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	canonical, err := scope.NewVersion(scope.VersionInput{ProjectID: version.ProjectID, Version: version.Version, CreatedAt: version.CreatedAt, Rules: version.Rules})
	if err != nil || canonical.Fingerprint != version.Fingerprint {
		return scope.ErrFingerprintMismatch
	}
	rules, err := json.Marshal(version.Rules)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO scope_authority_versions(project_id, scope_version, created_at, rules_json, fingerprint) VALUES(?, ?, ?, ?, ?)`, version.ProjectID, version.Version, version.CreatedAt.UTC().Format(time.RFC3339Nano), string(rules), version.Fingerprint)
	if err != nil {
		return fmt.Errorf("insert scope version: %w", err)
	}
	return nil
}

func (db *DB) LoadScopeVersion(ctx context.Context, projectID, versionID string) (scope.Version, error) {
	if db == nil || db.sql == nil {
		return scope.Version{}, errors.New("storage database is not initialized")
	}
	var version scope.Version
	var created, rules string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id, scope_version, created_at, rules_json, fingerprint FROM scope_authority_versions WHERE project_id = ? AND scope_version = ?`, projectID, versionID).Scan(&version.ProjectID, &version.Version, &created, &rules, &version.Fingerprint)
	if err != nil {
		return scope.Version{}, fmt.Errorf("load scope version: %w", err)
	}
	if version.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return scope.Version{}, err
	}
	if err = json.Unmarshal([]byte(rules), &version.Rules); err != nil {
		return scope.Version{}, err
	}
	return version, nil
}

func (db *DB) ListScopeVersions(ctx context.Context, projectID string) ([]scope.Version, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT scope_version FROM scope_authority_versions WHERE project_id = ? ORDER BY created_at DESC, scope_version`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list scope versions: %w", err)
	}
	defer rows.Close()
	versions := make([]scope.Version, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		version, err := db.LoadScopeVersion(ctx, projectID, id)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

var _ = sql.ErrNoRows
