package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type EvidenceCorrelationSnapshotRecord struct {
	ProjectID, CampaignID, FindingID, Fingerprint, VerificationState, FreshnessState, ReproducibilityState, SnapshotJSON string
	CreatedAt                                                                                                            time.Time
}

func (db *DB) SaveEvidenceCorrelationSnapshot(ctx context.Context, record EvidenceCorrelationSnapshotRecord) error {
	if db == nil || db.sql == nil || !validEvidenceCorrelationSnapshot(record) {
		return errors.New("invalid evidence correlation snapshot")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO evidence_correlation_snapshots(project_id,campaign_id,finding_id,fingerprint,verification_state,freshness_state,reproducibility_state,snapshot_json,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,campaign_id,finding_id,fingerprint) DO NOTHING`, record.ProjectID, record.CampaignID, record.FindingID, record.Fingerprint, record.VerificationState, record.FreshnessState, record.ReproducibilityState, record.SnapshotJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) ListEvidenceCorrelationSnapshots(ctx context.Context, projectID, campaignID string) ([]EvidenceCorrelationSnapshotRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, campaignID) {
		return nil, errors.New("invalid evidence correlation snapshot query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id,campaign_id,finding_id,fingerprint,verification_state,freshness_state,reproducibility_state,snapshot_json,created_at FROM evidence_correlation_snapshots WHERE project_id=? AND campaign_id=? ORDER BY created_at,finding_id,fingerprint`, projectID, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []EvidenceCorrelationSnapshotRecord{}
	for rows.Next() {
		var record EvidenceCorrelationSnapshotRecord
		var created string
		if err := rows.Scan(&record.ProjectID, &record.CampaignID, &record.FindingID, &record.Fingerprint, &record.VerificationState, &record.FreshnessState, &record.ReproducibilityState, &record.SnapshotJSON, &created); err != nil {
			return nil, err
		}
		if record.CreatedAt, err = parseStorageTime(created); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func validEvidenceCorrelationSnapshot(record EvidenceCorrelationSnapshotRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.FindingID, record.Fingerprint, record.VerificationState, record.FreshnessState, record.ReproducibilityState) && !record.CreatedAt.IsZero() && len(record.SnapshotJSON) > 0 && len(record.SnapshotJSON) <= 128<<10 && json.Valid([]byte(record.SnapshotJSON)) && !secretLike(record.SnapshotJSON) && strings.TrimSpace(record.SnapshotJSON) != ""
}
