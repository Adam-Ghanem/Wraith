package storage

import (
	"context"
	"errors"
	"strings"
	"time"
)

type IdentityRecord struct {
	ProjectID, IdentityID, Name, Role, Description, Status string
	CreatedAt, UpdatedAt                                   time.Time
}

func (db *DB) CreateIdentity(ctx context.Context, record IdentityRecord) error {
	if db == nil || db.sql == nil || !validIdentityRecord(record) {
		return errors.New("invalid project identity")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO identities(project_id, identity_id, name, role, description, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, record.ProjectID, record.IdentityID, record.Name, record.Role, record.Description, record.Status, record.CreatedAt.UTC().Format(time.RFC3339Nano), record.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (db *DB) ListIdentities(ctx context.Context, projectID string) ([]IdentityRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" {
		return nil, errors.New("invalid project identity query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, identity_id, name, role, description, status, created_at, updated_at FROM identities WHERE project_id=? ORDER BY name, identity_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []IdentityRecord{}
	for rows.Next() {
		var record IdentityRecord
		var created, updated string
		if err := rows.Scan(&record.ProjectID, &record.IdentityID, &record.Name, &record.Role, &record.Description, &record.Status, &created, &updated); err != nil {
			return nil, err
		}
		record.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		record.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func validIdentityRecord(record IdentityRecord) bool {
	return strings.TrimSpace(record.ProjectID) != "" && strings.TrimSpace(record.IdentityID) != "" && strings.TrimSpace(record.Name) != "" && len(record.Name) <= 128 && strings.TrimSpace(record.Role) != "" && len(record.Role) <= 128 && len(record.Description) <= 512 && (record.Status == "active" || record.Status == "stopped" || record.Status == "disabled") && !record.CreatedAt.IsZero() && !record.UpdatedAt.IsZero()
}
