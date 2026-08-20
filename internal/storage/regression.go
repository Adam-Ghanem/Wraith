package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type RegressionSnapshotRecord struct {
	ProjectID, SnapshotID, CampaignID, ScopeVersion, AssessmentID, SurfaceSnapshotID, SnapshotFingerprint, SnapshotJSON string
	CreatedAt                                                                                                           time.Time
}

type RegressionComparisonRecord struct {
	ProjectID, BaselineSnapshotID, CurrentSnapshotID, Fingerprint, ComparisonJSON string
	CreatedAt                                                                     time.Time
}

func (db *DB) SaveRegressionSnapshot(ctx context.Context, record RegressionSnapshotRecord) error {
	if db == nil || db.sql == nil || !validRegressionSnapshot(record) {
		return errors.New("invalid regression snapshot")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO regression_snapshots(project_id,snapshot_id,campaign_id,scope_version,assessment_id,surface_snapshot_id,snapshot_fingerprint,snapshot_json,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,snapshot_id) DO NOTHING`, record.ProjectID, record.SnapshotID, record.CampaignID, record.ScopeVersion, record.AssessmentID, record.SurfaceSnapshotID, record.SnapshotFingerprint, record.SnapshotJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) LoadRegressionSnapshot(ctx context.Context, projectID, snapshotID string) (RegressionSnapshotRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, snapshotID) {
		return RegressionSnapshotRecord{}, errors.New("invalid regression snapshot query")
	}
	var record RegressionSnapshotRecord
	var createdAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,snapshot_id,campaign_id,scope_version,assessment_id,surface_snapshot_id,snapshot_fingerprint,snapshot_json,created_at FROM regression_snapshots WHERE project_id=? AND snapshot_id=?`, projectID, snapshotID).Scan(&record.ProjectID, &record.SnapshotID, &record.CampaignID, &record.ScopeVersion, &record.AssessmentID, &record.SurfaceSnapshotID, &record.SnapshotFingerprint, &record.SnapshotJSON, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RegressionSnapshotRecord{}, errors.New("regression snapshot is absent from selected project")
	}
	if err != nil {
		return RegressionSnapshotRecord{}, err
	}
	record.CreatedAt, err = parseStorageTime(createdAt)
	return record, err
}

func (db *DB) SaveRegressionComparison(ctx context.Context, record RegressionComparisonRecord) error {
	if db == nil || db.sql == nil || !validRegressionComparison(record) {
		return errors.New("invalid regression comparison")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO regression_comparisons(project_id,baseline_snapshot_id,current_snapshot_id,fingerprint,comparison_json,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(project_id,baseline_snapshot_id,current_snapshot_id,fingerprint) DO NOTHING`, record.ProjectID, record.BaselineSnapshotID, record.CurrentSnapshotID, record.Fingerprint, record.ComparisonJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) ListRegressionComparisons(ctx context.Context, projectID string) ([]RegressionComparisonRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) {
		return nil, errors.New("invalid regression comparison query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id,baseline_snapshot_id,current_snapshot_id,fingerprint,comparison_json,created_at FROM regression_comparisons WHERE project_id=? ORDER BY created_at,baseline_snapshot_id,current_snapshot_id,fingerprint`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	comparisons := []RegressionComparisonRecord{}
	for rows.Next() {
		var record RegressionComparisonRecord
		var createdAt string
		if err := rows.Scan(&record.ProjectID, &record.BaselineSnapshotID, &record.CurrentSnapshotID, &record.Fingerprint, &record.ComparisonJSON, &createdAt); err != nil {
			return nil, err
		}
		if record.CreatedAt, err = parseStorageTime(createdAt); err != nil {
			return nil, err
		}
		comparisons = append(comparisons, record)
	}
	return comparisons, rows.Err()
}

func validRegressionSnapshot(record RegressionSnapshotRecord) bool {
	return requiredSecretFree(record.ProjectID, record.SnapshotID, record.CampaignID, record.ScopeVersion, record.SnapshotFingerprint) && optionalSecretFree(record.AssessmentID, record.SurfaceSnapshotID) && validRegressionJSON(record.SnapshotJSON) && validFingerprint(record.SnapshotFingerprint) && !record.CreatedAt.IsZero()
}

func validRegressionComparison(record RegressionComparisonRecord) bool {
	return requiredSecretFree(record.ProjectID, record.BaselineSnapshotID, record.CurrentSnapshotID, record.Fingerprint) && record.BaselineSnapshotID != record.CurrentSnapshotID && validRegressionJSON(record.ComparisonJSON) && validFingerprint(record.Fingerprint) && !record.CreatedAt.IsZero()
}

func validRegressionJSON(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 128<<10 && json.Valid([]byte(value)) && !secretLike(value)
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func optionalSecretFree(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && hasSecretLikeStorage(value) {
			return false
		}
	}
	return true
}
