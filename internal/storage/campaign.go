package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type CampaignRecord struct {
	ProjectID, CampaignID, ScopeVersion, Profile, AssessmentID, Target, AssessmentPlanJSON, SurfaceSnapshotID, SurfaceFingerprint, SurfaceSourceVersion, Status, Fingerprint, LastCheckpointID string
	Revision                                                                                                                                                                                   int
	CreatedAt, StartedAt, FinishedAt, CancelledAt                                                                                                                                              time.Time
}

type CampaignCycleRecord struct {
	ProjectID, CampaignID, CycleID, ScopeVersion, AssessmentID, SurfaceSnapshotID, Status, ExecutionRunID string
	CreatedAt, StartedAt, FinishedAt                                                                      time.Time
}

type CampaignTaskRecord struct {
	ProjectID, CampaignID, CycleID, TaskID, AssessmentTaskID, Status, ResultReference string
	Priority, Attempt                                                                 int
	StartedAt, FinishedAt                                                             time.Time
}

type CampaignCheckpointRecord struct {
	ProjectID, CampaignID, CycleID, CheckpointID, ScopeVersion, SurfaceSnapshotID, Fingerprint string
	Sequence                                                                                   int
	CompletedTaskIDsJSON, PendingTaskIDsJSON, BlockedTaskIDsJSON, FailedTaskIDsJSON            string
	CreatedAt                                                                                  time.Time
}

type CampaignEventRecord struct {
	ProjectID, CampaignID, EventID, CycleID, TaskID, EventType, Status, Reason, MetadataJSON string
	CreatedAt                                                                                time.Time
}

func (db *DB) CreateCampaign(ctx context.Context, record CampaignRecord) error {
	if db == nil || db.sql == nil || !validCampaignRecord(record) {
		return errors.New("invalid campaign record")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO campaigns(project_id,campaign_id,scope_version,profile,assessment_id,target,assessment_plan_json,surface_snapshot_id,surface_fingerprint,surface_source_version,status,revision,fingerprint,last_checkpoint_id,created_at,started_at,finished_at,cancelled_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.ProjectID, record.CampaignID, record.ScopeVersion, record.Profile, record.AssessmentID, record.Target, record.AssessmentPlanJSON, record.SurfaceSnapshotID, record.SurfaceFingerprint, record.SurfaceSourceVersion, record.Status, record.Revision, record.Fingerprint, record.LastCheckpointID, record.CreatedAt.UTC().Format(time.RFC3339Nano), nullableTime(record.StartedAt), nullableTime(record.FinishedAt), nullableTime(record.CancelledAt))
	return err
}

func (db *DB) LoadCampaign(ctx context.Context, projectID, campaignID string) (CampaignRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" || strings.TrimSpace(campaignID) == "" {
		return CampaignRecord{}, errors.New("invalid campaign query")
	}
	var record CampaignRecord
	var created, started, finished, cancelled string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,campaign_id,scope_version,profile,assessment_id,target,assessment_plan_json,surface_snapshot_id,surface_fingerprint,surface_source_version,status,revision,fingerprint,last_checkpoint_id,created_at,COALESCE(started_at,''),COALESCE(finished_at,''),COALESCE(cancelled_at,'') FROM campaigns WHERE project_id=? AND campaign_id=?`, projectID, campaignID).Scan(&record.ProjectID, &record.CampaignID, &record.ScopeVersion, &record.Profile, &record.AssessmentID, &record.Target, &record.AssessmentPlanJSON, &record.SurfaceSnapshotID, &record.SurfaceFingerprint, &record.SurfaceSourceVersion, &record.Status, &record.Revision, &record.Fingerprint, &record.LastCheckpointID, &created, &started, &finished, &cancelled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CampaignRecord{}, errors.New("campaign is absent from selected project")
		}
		return CampaignRecord{}, err
	}
	if err := parseCampaignTimes(&record, created, started, finished, cancelled); err != nil {
		return CampaignRecord{}, err
	}
	return record, nil
}

func (db *DB) CreateCampaignCycle(ctx context.Context, record CampaignCycleRecord) error {
	if db == nil || db.sql == nil || !validCycleRecord(record) {
		return errors.New("invalid campaign cycle")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO campaign_cycles(project_id,campaign_id,cycle_id,scope_version,assessment_id,surface_snapshot_id,status,execution_run_id,created_at,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, record.ProjectID, record.CampaignID, record.CycleID, record.ScopeVersion, record.AssessmentID, record.SurfaceSnapshotID, record.Status, record.ExecutionRunID, record.CreatedAt.UTC().Format(time.RFC3339Nano), nullableTime(record.StartedAt), nullableTime(record.FinishedAt))
	return err
}

func (db *DB) UpdateCampaignStatus(ctx context.Context, projectID, campaignID, status, checkpointID string, now time.Time) error {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, campaignID, status) || !validCampaignStatus(status) || hasSecretLikeStorage(checkpointID) || now.IsZero() {
		return errors.New("invalid campaign status update")
	}
	finished := ""
	if status == "completed" || status == "failed" || status == "cancelled" || status == "expired" {
		finished = now.UTC().Format(time.RFC3339Nano)
	}
	result, err := db.sql.ExecContext(ctx, `UPDATE campaigns SET status=?,last_checkpoint_id=?,revision=revision+1,started_at=COALESCE(started_at,?),finished_at=CASE WHEN ?='' THEN finished_at ELSE ? END,cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE cancelled_at END WHERE project_id=? AND campaign_id=?`, status, checkpointID, now.UTC().Format(time.RFC3339Nano), finished, finished, status, now.UTC().Format(time.RFC3339Nano), projectID, campaignID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("campaign is absent from selected project")
	}
	return nil
}

func (db *DB) UpdateCampaignCycleStatus(ctx context.Context, projectID, campaignID, cycleID, status, executionRunID string, now time.Time) error {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, campaignID, cycleID, status) || hasSecretLikeStorage(executionRunID) || !validCampaignStatus(status) || now.IsZero() {
		return errors.New("invalid campaign cycle status update")
	}
	finished := ""
	if status == "completed" || status == "failed" || status == "cancelled" || status == "expired" || status == "paused" {
		finished = now.UTC().Format(time.RFC3339Nano)
	}
	result, err := db.sql.ExecContext(ctx, `UPDATE campaign_cycles SET status=?,execution_run_id=?,started_at=COALESCE(started_at,?),finished_at=CASE WHEN ?='' THEN finished_at ELSE ? END WHERE project_id=? AND campaign_id=? AND cycle_id=?`, status, executionRunID, now.UTC().Format(time.RFC3339Nano), finished, finished, projectID, campaignID, cycleID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("campaign cycle is absent from selected project")
	}
	return nil
}

func (db *DB) UpsertCampaignTask(ctx context.Context, record CampaignTaskRecord) error {
	if db == nil || db.sql == nil || !validTaskRecord(record) {
		return errors.New("invalid campaign task")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO campaign_tasks(project_id,campaign_id,cycle_id,task_id,assessment_task_id,status,priority,attempt,result_reference,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,campaign_id,cycle_id,task_id) DO UPDATE SET status=excluded.status,attempt=excluded.attempt,result_reference=excluded.result_reference,started_at=COALESCE(campaign_tasks.started_at,excluded.started_at),finished_at=excluded.finished_at`, record.ProjectID, record.CampaignID, record.CycleID, record.TaskID, record.AssessmentTaskID, record.Status, record.Priority, record.Attempt, record.ResultReference, nullableTime(record.StartedAt), nullableTime(record.FinishedAt))
	return err
}

func (db *DB) CreateCampaignCheckpoint(ctx context.Context, record CampaignCheckpointRecord) error {
	if db == nil || db.sql == nil || !validCheckpointRecord(record) {
		return errors.New("invalid campaign checkpoint")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO campaign_checkpoints(project_id,campaign_id,cycle_id,checkpoint_id,sequence,scope_version,surface_snapshot_id,fingerprint,completed_task_ids_json,pending_task_ids_json,blocked_task_ids_json,failed_task_ids_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.ProjectID, record.CampaignID, record.CycleID, record.CheckpointID, record.Sequence, record.ScopeVersion, record.SurfaceSnapshotID, record.Fingerprint, record.CompletedTaskIDsJSON, record.PendingTaskIDsJSON, record.BlockedTaskIDsJSON, record.FailedTaskIDsJSON, record.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (db *DB) LoadLatestCampaignCheckpoint(ctx context.Context, projectID, campaignID, cycleID string) (CampaignCheckpointRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" || strings.TrimSpace(campaignID) == "" || strings.TrimSpace(cycleID) == "" {
		return CampaignCheckpointRecord{}, errors.New("invalid campaign checkpoint query")
	}
	var record CampaignCheckpointRecord
	var created string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,campaign_id,cycle_id,checkpoint_id,sequence,scope_version,surface_snapshot_id,fingerprint,completed_task_ids_json,pending_task_ids_json,blocked_task_ids_json,failed_task_ids_json,created_at FROM campaign_checkpoints WHERE project_id=? AND campaign_id=? AND cycle_id=? ORDER BY sequence DESC, checkpoint_id DESC LIMIT 1`, projectID, campaignID, cycleID).Scan(&record.ProjectID, &record.CampaignID, &record.CycleID, &record.CheckpointID, &record.Sequence, &record.ScopeVersion, &record.SurfaceSnapshotID, &record.Fingerprint, &record.CompletedTaskIDsJSON, &record.PendingTaskIDsJSON, &record.BlockedTaskIDsJSON, &record.FailedTaskIDsJSON, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CampaignCheckpointRecord{}, errors.New("campaign checkpoint is absent from selected project")
		}
		return CampaignCheckpointRecord{}, err
	}
	record.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return record, err
}

func (db *DB) LoadLatestCampaignCheckpointForCampaign(ctx context.Context, projectID, campaignID string) (CampaignCheckpointRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" || strings.TrimSpace(campaignID) == "" {
		return CampaignCheckpointRecord{}, errors.New("invalid campaign checkpoint query")
	}
	var record CampaignCheckpointRecord
	var created string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,campaign_id,cycle_id,checkpoint_id,sequence,scope_version,surface_snapshot_id,fingerprint,completed_task_ids_json,pending_task_ids_json,blocked_task_ids_json,failed_task_ids_json,created_at FROM campaign_checkpoints WHERE project_id=? AND campaign_id=? ORDER BY created_at DESC, sequence DESC, checkpoint_id DESC LIMIT 1`, projectID, campaignID).Scan(&record.ProjectID, &record.CampaignID, &record.CycleID, &record.CheckpointID, &record.Sequence, &record.ScopeVersion, &record.SurfaceSnapshotID, &record.Fingerprint, &record.CompletedTaskIDsJSON, &record.PendingTaskIDsJSON, &record.BlockedTaskIDsJSON, &record.FailedTaskIDsJSON, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CampaignCheckpointRecord{}, errors.New("campaign checkpoint is absent from selected project")
		}
		return CampaignCheckpointRecord{}, err
	}
	record.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return record, err
}

func (db *DB) AppendCampaignEvent(ctx context.Context, record CampaignEventRecord) error {
	if db == nil || db.sql == nil || !validEventRecord(record) {
		return errors.New("invalid campaign event")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO campaign_events(project_id,campaign_id,event_id,cycle_id,task_id,event_type,status,reason,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, record.ProjectID, record.CampaignID, record.EventID, record.CycleID, record.TaskID, record.EventType, record.Status, record.Reason, record.MetadataJSON, record.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func validCampaignRecord(record CampaignRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.ScopeVersion, record.Profile, record.AssessmentID, record.Target, record.SurfaceSnapshotID, record.SurfaceFingerprint, record.SurfaceSourceVersion, record.Status, record.Fingerprint) && validPlanJSON(record.AssessmentPlanJSON) && validProfile(record.Profile) && validCampaignStatus(record.Status) && record.Revision >= 1 && !record.CreatedAt.IsZero()
}

func validCycleRecord(record CampaignCycleRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.CycleID, record.ScopeVersion, record.AssessmentID, record.SurfaceSnapshotID, record.Status) && validCampaignStatus(record.Status) && !record.CreatedAt.IsZero()
}

func validTaskRecord(record CampaignTaskRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.CycleID, record.TaskID, record.AssessmentTaskID, record.Status) && validCampaignTaskStatus(record.Status) && record.Attempt >= 0 && !hasSecretLikeStorage(record.ResultReference)
}

func validCheckpointRecord(record CampaignCheckpointRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.CycleID, record.CheckpointID, record.ScopeVersion, record.SurfaceSnapshotID, record.Fingerprint) && record.Sequence >= 1 && !record.CreatedAt.IsZero() && validTaskIDJSON(record.CompletedTaskIDsJSON) && validTaskIDJSON(record.PendingTaskIDsJSON) && validTaskIDJSON(record.BlockedTaskIDsJSON) && validTaskIDJSON(record.FailedTaskIDsJSON)
}

func validEventRecord(record CampaignEventRecord) bool {
	return requiredSecretFree(record.ProjectID, record.CampaignID, record.EventID, record.EventType, record.Status) && !hasSecretLikeStorage(record.CycleID) && !hasSecretLikeStorage(record.TaskID) && !hasSecretLikeStorage(record.Reason) && record.MetadataJSON == "{}" && !record.CreatedAt.IsZero()
}

func requiredSecretFree(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" || hasSecretLikeStorage(value) {
			return false
		}
	}
	return true
}

func hasSecretLikeStorage(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "token=", "token:", "secret", "authorization", "cookie", "bearer", "api_key", "apikey", "@"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func validTaskIDJSON(value string) bool {
	var ids []string
	if err := json.Unmarshal([]byte(value), &ids); err != nil {
		return false
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || hasSecretLikeStorage(id) {
			return false
		}
		if _, exists := seen[id]; exists {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func validPlanJSON(value string) bool {
	var plan map[string]any
	return json.Unmarshal([]byte(value), &plan) == nil && len(plan) > 0 && !hasSecretLikeStorage(value)
}

func validProfile(profile string) bool {
	return profile == "safe" || profile == "standard" || profile == "deep"
}

func validCampaignStatus(status string) bool {
	switch status {
	case "draft", "planned", "ready", "running", "paused", "completed", "failed", "cancelled", "expired":
		return true
	}
	return false
}

func validCampaignTaskStatus(status string) bool {
	switch status {
	case "pending", "ready", "running", "completed", "failed", "blocked", "skipped", "cancelled", "expired":
		return true
	}
	return false
}

func parseCampaignTimes(record *CampaignRecord, created, started, finished, cancelled string) error {
	var err error
	if record.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return err
	}
	for _, pair := range []struct {
		raw string
		out *time.Time
	}{{started, &record.StartedAt}, {finished, &record.FinishedAt}, {cancelled, &record.CancelledAt}} {
		if pair.raw == "" {
			continue
		}
		if *pair.out, err = time.Parse(time.RFC3339Nano, pair.raw); err != nil {
			return err
		}
	}
	return nil
}
