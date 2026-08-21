package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/dataprotection"
)

var (
	ErrDataProtectionSnapshotExists   = errors.New("data protection snapshot already exists")
	ErrDataProtectionSnapshotNotFound = errors.New("data protection snapshot not found")
)

// SaveDataProtectionSnapshot persists one immutable, secret-free snapshot. A
// conflict is refused so callers must create a new snapshot for new state.
func (db *DB) SaveDataProtectionSnapshot(ctx context.Context, snapshot dataprotection.Snapshot) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := dataprotection.ValidateSnapshot(snapshot); err != nil {
		return err
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin data protection snapshot transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO data_protection_snapshots(project_id, snapshot_id, descriptor_fingerprint, decision_fingerprint, profile, classification, version, created_at, expires_at, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, snapshot_id) DO NOTHING`, snapshot.ProjectID, snapshot.SnapshotID, snapshot.DescriptorFingerprint, snapshot.DecisionFingerprint, snapshot.Profile, snapshot.Classification, snapshot.Version, formatRequiredPolicyTime(snapshot.CreatedAt), optionalProtectionTime(snapshot.ExpiresAt), snapshot.Fingerprint)
	if err != nil {
		return fmt.Errorf("insert data protection snapshot: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read data protection snapshot insert result: %w", err)
	}
	if rows == 0 {
		return ErrDataProtectionSnapshotExists
	}
	event, err := dataclassification.NewGovernanceEvent(dataclassification.GovernanceEventInput{ProjectID: snapshot.ProjectID, SubjectReference: snapshot.SnapshotID, EventType: dataclassification.EventPersistenceAllowed, Classification: snapshot.Classification, OccurredAt: snapshot.CreatedAt})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO data_governance_audit_events(project_id, subject_reference, event_type, classification, policy_version, occurred_at, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?)`, event.ProjectID, event.SubjectReference, event.EventType, event.Classification, event.PolicyVersion, formatRequiredPolicyTime(event.OccurredAt), event.Fingerprint); err != nil {
		return fmt.Errorf("append data protection audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit data protection snapshot: %w", err)
	}
	return nil
}

// LoadDataProtectionSnapshot accepts only one revalidated snapshot owned by
// the requested project; there is no cross-project fallback.
func (db *DB) LoadDataProtectionSnapshot(ctx context.Context, projectID, snapshotID string) (dataprotection.Snapshot, error) {
	if db == nil || db.sql == nil {
		return dataprotection.Snapshot{}, errors.New("storage database is not initialized")
	}
	projectID, snapshotID = strings.TrimSpace(projectID), strings.TrimSpace(snapshotID)
	if dataclassification.ValidateSafeText(projectID, 256) != nil || dataclassification.ValidateSafeReference(snapshotID) != nil {
		return dataprotection.Snapshot{}, dataprotection.ErrDescriptorInvalid
	}
	var snapshot dataprotection.Snapshot
	var createdAt string
	var expiresAt sql.NullString
	err := db.sql.QueryRowContext(ctx, `SELECT project_id, snapshot_id, descriptor_fingerprint, decision_fingerprint, profile, classification, version, created_at, expires_at, fingerprint FROM data_protection_snapshots WHERE project_id = ? AND snapshot_id = ?`, projectID, snapshotID).Scan(&snapshot.ProjectID, &snapshot.SnapshotID, &snapshot.DescriptorFingerprint, &snapshot.DecisionFingerprint, &snapshot.Profile, &snapshot.Classification, &snapshot.Version, &createdAt, &expiresAt, &snapshot.Fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return dataprotection.Snapshot{}, ErrDataProtectionSnapshotNotFound
	}
	if err != nil {
		return dataprotection.Snapshot{}, fmt.Errorf("load data protection snapshot: %w", err)
	}
	var parseErr error
	if snapshot.CreatedAt, parseErr = parseRequiredPolicyTime(createdAt); parseErr != nil {
		return dataprotection.Snapshot{}, fmt.Errorf("decode data protection snapshot creation time: %w", parseErr)
	}
	if expiresAt.Valid {
		if snapshot.ExpiresAt, parseErr = parseRequiredPolicyTime(expiresAt.String); parseErr != nil {
			return dataprotection.Snapshot{}, fmt.Errorf("decode data protection snapshot expiration time: %w", parseErr)
		}
	}
	if err := dataprotection.ValidateSnapshot(snapshot); err != nil {
		return dataprotection.Snapshot{}, err
	}
	return snapshot, nil
}

func optionalProtectionTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return formatRequiredPolicyTime(value)
}
