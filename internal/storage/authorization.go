package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

var ErrAuthorizationRecordExists = errors.New("authorization record already exists")

func (db *DB) SaveAuthorizationRecord(ctx context.Context, record authorization.Record) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := authorization.Validate(record, authorization.ValidationRequest{ProjectID: record.ProjectID, ScopeReference: record.ScopeReference, Now: record.IssuedAt}); err != nil {
		return fmt.Errorf("validate authorization record: %w", err)
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO authorization_records(authorization_id, project_id, subject, scope_reference, authorization_type, issued_at, expires_at, revoked_at, status, evidence_reference, created_by, fingerprint, schema_version) VALUES(?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`, record.AuthorizationID, record.ProjectID, record.Subject, record.ScopeReference, record.Type, record.IssuedAt.UTC().Format(time.RFC3339Nano), record.ExpiresAt.UTC().Format(time.RFC3339Nano), record.Status, record.EvidenceReference, record.CreatedBy, record.Fingerprint, record.SchemaVersion)
	if err != nil {
		return fmt.Errorf("insert authorization record: %w", err)
	}
	return nil
}

func (db *DB) LoadAuthorizationRecord(ctx context.Context, projectID, authorizationID string) (authorization.Record, error) {
	if db == nil || db.sql == nil {
		return authorization.Record{}, errors.New("storage database is not initialized")
	}
	var record authorization.Record
	var revoked sql.NullString
	var issued, expires string
	err := db.sql.QueryRowContext(ctx, `SELECT authorization_id, project_id, subject, scope_reference, authorization_type, issued_at, expires_at, revoked_at, status, evidence_reference, created_by, fingerprint, schema_version FROM authorization_records WHERE project_id = ? AND authorization_id = ?`, projectID, authorizationID).Scan(&record.AuthorizationID, &record.ProjectID, &record.Subject, &record.ScopeReference, &record.Type, &issued, &expires, &revoked, &record.Status, &record.EvidenceReference, &record.CreatedBy, &record.Fingerprint, &record.SchemaVersion)
	if err != nil {
		return authorization.Record{}, fmt.Errorf("load authorization record: %w", err)
	}
	var parseErr error
	if record.IssuedAt, parseErr = time.Parse(time.RFC3339Nano, issued); parseErr != nil {
		return authorization.Record{}, fmt.Errorf("parse authorization issuance: %w", parseErr)
	}
	if record.ExpiresAt, parseErr = time.Parse(time.RFC3339Nano, expires); parseErr != nil {
		return authorization.Record{}, fmt.Errorf("parse authorization expiry: %w", parseErr)
	}
	if revoked.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, revoked.String)
		if err != nil {
			return authorization.Record{}, fmt.Errorf("parse authorization revocation: %w", err)
		}
		record.RevokedAt = &parsed
	}
	return record, nil
}

func (db *DB) ListAuthorizationRecords(ctx context.Context, projectID string) ([]authorization.Record, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT authorization_id FROM authorization_records WHERE project_id = ? ORDER BY issued_at DESC, authorization_id`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list authorization records: %w", err)
	}
	defer rows.Close()
	result := make([]authorization.Record, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		record, err := db.LoadAuthorizationRecord(ctx, projectID, id)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (db *DB) RevokeAuthorizationRecord(ctx context.Context, projectID string, record authorization.Record) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if record.ProjectID != projectID || record.Status != authorization.StatusRevoked || record.RevokedAt == nil {
		return authorization.ErrInvalidRecord
	}
	previous, err := db.LoadAuthorizationRecord(ctx, projectID, record.AuthorizationID)
	if err != nil {
		return err
	}
	if err := authorization.Validate(previous, authorization.ValidationRequest{ProjectID: projectID, ScopeReference: previous.ScopeReference, Now: previous.IssuedAt}); err != nil {
		return fmt.Errorf("validate stored authorization before revocation: %w", err)
	}
	if previous.Fingerprint == record.Fingerprint || previous.ProjectID != record.ProjectID || previous.ScopeReference != record.ScopeReference {
		return authorization.ErrInvalidRecord
	}
	result, err := db.sql.ExecContext(ctx, `UPDATE authorization_records SET revoked_at = ?, status = ?, fingerprint = ? WHERE project_id = ? AND authorization_id = ? AND fingerprint = ? AND status = ?`, record.RevokedAt.UTC().Format(time.RFC3339Nano), record.Status, record.Fingerprint, projectID, record.AuthorizationID, previous.Fingerprint, authorization.StatusActive)
	if err != nil {
		return fmt.Errorf("revoke authorization record: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return authorization.ErrInvalidRecord
	}
	return nil
}
