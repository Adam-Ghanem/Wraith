package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type AssessmentPolicyRecord struct {
	ProjectID, PolicyID, Name, Fingerprint, PolicyJSON string
	Version                                            int
	CreatedAt                                          time.Time
}

type AssessmentBaselineRecord struct {
	ProjectID, BaselineID, SnapshotID, PolicyID, CampaignID, Fingerprint, BaselineJSON string
	CreatedAt                                                                          time.Time
}

type AssessmentEvaluationRecord struct {
	ProjectID, EvaluationID, PolicyID, BaselineID, BaselineSnapshotID, CurrentSnapshotID, ComparisonID, Status, Fingerprint, EvaluationJSON string
	CreatedAt                                                                                                                               time.Time
}

type AssessmentActionRecord struct {
	ProjectID, ActionID, EvaluationID, RuleID, Kind, Priority, Status, CampaignID, Fingerprint, ActionJSON string
	CreatedAt                                                                                              time.Time
}

func (db *DB) SaveAssessmentPolicy(ctx context.Context, record AssessmentPolicyRecord) error {
	if db == nil || db.sql == nil || !validAssessmentPolicy(record) {
		return errors.New("invalid assessment policy")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO assessment_policies(project_id,policy_id,name,policy_version,fingerprint,policy_json,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(project_id,policy_id) DO NOTHING`, record.ProjectID, record.PolicyID, record.Name, record.Version, record.Fingerprint, record.PolicyJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) LoadAssessmentPolicy(ctx context.Context, projectID, policyID string) (AssessmentPolicyRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, policyID) {
		return AssessmentPolicyRecord{}, errors.New("invalid assessment policy query")
	}
	var record AssessmentPolicyRecord
	var createdAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,policy_id,name,policy_version,fingerprint,policy_json,created_at FROM assessment_policies WHERE project_id=? AND policy_id=?`, projectID, policyID).Scan(&record.ProjectID, &record.PolicyID, &record.Name, &record.Version, &record.Fingerprint, &record.PolicyJSON, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentPolicyRecord{}, errors.New("assessment policy is absent from selected project")
	}
	if err != nil {
		return AssessmentPolicyRecord{}, err
	}
	record.CreatedAt, err = parseStorageTime(createdAt)
	return record, err
}

func (db *DB) ListAssessmentPolicies(ctx context.Context, projectID string) ([]AssessmentPolicyRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) {
		return nil, errors.New("invalid assessment policy query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id,policy_id,name,policy_version,fingerprint,policy_json,created_at FROM assessment_policies WHERE project_id=? ORDER BY created_at,policy_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []AssessmentPolicyRecord{}
	for rows.Next() {
		var record AssessmentPolicyRecord
		var createdAt string
		if err := rows.Scan(&record.ProjectID, &record.PolicyID, &record.Name, &record.Version, &record.Fingerprint, &record.PolicyJSON, &createdAt); err != nil {
			return nil, err
		}
		if record.CreatedAt, err = parseStorageTime(createdAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (db *DB) SaveAssessmentBaseline(ctx context.Context, record AssessmentBaselineRecord) error {
	if db == nil || db.sql == nil || !validAssessmentBaseline(record) {
		return errors.New("invalid assessment baseline")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO assessment_baselines(project_id,baseline_id,snapshot_id,policy_id,campaign_id,fingerprint,baseline_json,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project_id,baseline_id) DO NOTHING`, record.ProjectID, record.BaselineID, record.SnapshotID, record.PolicyID, nullableAssessmentString(record.CampaignID), record.Fingerprint, record.BaselineJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) LoadAssessmentBaseline(ctx context.Context, projectID, baselineID string) (AssessmentBaselineRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, baselineID) {
		return AssessmentBaselineRecord{}, errors.New("invalid assessment baseline query")
	}
	var record AssessmentBaselineRecord
	var createdAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,baseline_id,snapshot_id,policy_id,COALESCE(campaign_id,''),fingerprint,baseline_json,created_at FROM assessment_baselines WHERE project_id=? AND baseline_id=?`, projectID, baselineID).Scan(&record.ProjectID, &record.BaselineID, &record.SnapshotID, &record.PolicyID, &record.CampaignID, &record.Fingerprint, &record.BaselineJSON, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentBaselineRecord{}, errors.New("assessment baseline is absent from selected project")
	}
	if err != nil {
		return AssessmentBaselineRecord{}, err
	}
	record.CreatedAt, err = parseStorageTime(createdAt)
	return record, err
}

func (db *DB) SaveAssessmentEvaluation(ctx context.Context, record AssessmentEvaluationRecord) error {
	if db == nil || db.sql == nil || !validAssessmentEvaluation(record) {
		return errors.New("invalid assessment evaluation")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO assessment_evaluations(project_id,evaluation_id,policy_id,baseline_id,baseline_snapshot_id,current_snapshot_id,comparison_id,status,fingerprint,evaluation_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,evaluation_id) DO NOTHING`, record.ProjectID, record.EvaluationID, record.PolicyID, record.BaselineID, record.BaselineSnapshotID, record.CurrentSnapshotID, record.ComparisonID, record.Status, record.Fingerprint, record.EvaluationJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) LoadAssessmentEvaluation(ctx context.Context, projectID, evaluationID string) (AssessmentEvaluationRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, evaluationID) {
		return AssessmentEvaluationRecord{}, errors.New("invalid assessment evaluation query")
	}
	var record AssessmentEvaluationRecord
	var createdAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,evaluation_id,policy_id,baseline_id,baseline_snapshot_id,current_snapshot_id,comparison_id,status,fingerprint,evaluation_json,created_at FROM assessment_evaluations WHERE project_id=? AND evaluation_id=?`, projectID, evaluationID).Scan(&record.ProjectID, &record.EvaluationID, &record.PolicyID, &record.BaselineID, &record.BaselineSnapshotID, &record.CurrentSnapshotID, &record.ComparisonID, &record.Status, &record.Fingerprint, &record.EvaluationJSON, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentEvaluationRecord{}, errors.New("assessment evaluation is absent from selected project")
	}
	if err != nil {
		return AssessmentEvaluationRecord{}, err
	}
	record.CreatedAt, err = parseStorageTime(createdAt)
	return record, err
}

func (db *DB) ListAssessmentEvaluations(ctx context.Context, projectID string) ([]AssessmentEvaluationRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) {
		return nil, errors.New("invalid assessment evaluation query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id,evaluation_id,policy_id,baseline_id,baseline_snapshot_id,current_snapshot_id,comparison_id,status,fingerprint,evaluation_json,created_at FROM assessment_evaluations WHERE project_id=? ORDER BY created_at,evaluation_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []AssessmentEvaluationRecord{}
	for rows.Next() {
		var record AssessmentEvaluationRecord
		var createdAt string
		if err := rows.Scan(&record.ProjectID, &record.EvaluationID, &record.PolicyID, &record.BaselineID, &record.BaselineSnapshotID, &record.CurrentSnapshotID, &record.ComparisonID, &record.Status, &record.Fingerprint, &record.EvaluationJSON, &createdAt); err != nil {
			return nil, err
		}
		if record.CreatedAt, err = parseStorageTime(createdAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (db *DB) SaveAssessmentAction(ctx context.Context, record AssessmentActionRecord) error {
	if db == nil || db.sql == nil || !validAssessmentAction(record) {
		return errors.New("invalid assessment action")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO assessment_actions(project_id,action_id,evaluation_id,rule_id,kind,priority,status,campaign_id,fingerprint,action_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,action_id) DO NOTHING`, record.ProjectID, record.ActionID, record.EvaluationID, record.RuleID, record.Kind, record.Priority, record.Status, nullableAssessmentString(record.CampaignID), record.Fingerprint, record.ActionJSON, formatStorageTime(record.CreatedAt))
	return err
}

func (db *DB) ListAssessmentActions(ctx context.Context, projectID, evaluationID string) ([]AssessmentActionRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, evaluationID) {
		return nil, errors.New("invalid assessment action query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id,action_id,evaluation_id,rule_id,kind,priority,status,COALESCE(campaign_id,''),fingerprint,action_json,created_at FROM assessment_actions WHERE project_id=? AND evaluation_id=? ORDER BY created_at,action_id`, projectID, evaluationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []AssessmentActionRecord{}
	for rows.Next() {
		var record AssessmentActionRecord
		var createdAt string
		if err := rows.Scan(&record.ProjectID, &record.ActionID, &record.EvaluationID, &record.RuleID, &record.Kind, &record.Priority, &record.Status, &record.CampaignID, &record.Fingerprint, &record.ActionJSON, &createdAt); err != nil {
			return nil, err
		}
		if record.CreatedAt, err = parseStorageTime(createdAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (db *DB) LoadAssessmentAction(ctx context.Context, projectID, actionID string) (AssessmentActionRecord, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, actionID) || !validFingerprint(actionID) {
		return AssessmentActionRecord{}, errors.New("invalid assessment action query")
	}
	var record AssessmentActionRecord
	var createdAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id,action_id,evaluation_id,rule_id,kind,priority,status,COALESCE(campaign_id,''),fingerprint,action_json,created_at FROM assessment_actions WHERE project_id=? AND action_id=?`, projectID, actionID).Scan(&record.ProjectID, &record.ActionID, &record.EvaluationID, &record.RuleID, &record.Kind, &record.Priority, &record.Status, &record.CampaignID, &record.Fingerprint, &record.ActionJSON, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentActionRecord{}, errors.New("assessment action is absent from selected project")
	}
	if err != nil {
		return AssessmentActionRecord{}, err
	}
	record.CreatedAt, err = parseStorageTime(createdAt)
	if err != nil || !validAssessmentAction(record) {
		return AssessmentActionRecord{}, errors.New("invalid persisted assessment action")
	}
	return record, nil
}

func validAssessmentPolicy(record AssessmentPolicyRecord) bool {
	return requiredSecretFree(record.ProjectID, record.PolicyID, record.Name, record.Fingerprint) && record.Version > 0 && validFingerprint(record.PolicyID) && validFingerprint(record.Fingerprint) && validAssessmentJSON(record.PolicyJSON) && !record.CreatedAt.IsZero()
}

func validAssessmentBaseline(record AssessmentBaselineRecord) bool {
	return requiredSecretFree(record.ProjectID, record.BaselineID, record.SnapshotID, record.PolicyID, record.Fingerprint) && optionalSecretFree(record.CampaignID) && validFingerprint(record.BaselineID) && validFingerprint(record.SnapshotID) && validFingerprint(record.PolicyID) && validFingerprint(record.Fingerprint) && validAssessmentJSON(record.BaselineJSON) && !record.CreatedAt.IsZero()
}

func validAssessmentEvaluation(record AssessmentEvaluationRecord) bool {
	return requiredSecretFree(record.ProjectID, record.EvaluationID, record.PolicyID, record.BaselineID, record.BaselineSnapshotID, record.CurrentSnapshotID, record.ComparisonID, record.Status, record.Fingerprint) && validFingerprint(record.EvaluationID) && validFingerprint(record.PolicyID) && validFingerprint(record.BaselineID) && validFingerprint(record.BaselineSnapshotID) && validFingerprint(record.CurrentSnapshotID) && validFingerprint(record.ComparisonID) && validFingerprint(record.Fingerprint) && validAssessmentStatus(record.Status) && validAssessmentJSON(record.EvaluationJSON) && !record.CreatedAt.IsZero()
}

func validAssessmentAction(record AssessmentActionRecord) bool {
	return requiredSecretFree(record.ProjectID, record.ActionID, record.EvaluationID, record.RuleID, record.Kind, record.Priority, record.Status, record.Fingerprint) && optionalSecretFree(record.CampaignID) && validFingerprint(record.ActionID) && validFingerprint(record.EvaluationID) && validFingerprint(record.Fingerprint) && validActionKind(record.Kind) && validActionPriority(record.Priority) && record.Status == "recommended" && validAssessmentJSON(record.ActionJSON) && !record.CreatedAt.IsZero()
}

func validAssessmentStatus(status string) bool {
	return status == "passed" || status == "failed" || status == "warning" || status == "unknown" || status == "informational"
}

func validActionKind(kind string) bool {
	switch kind {
	case "reverify_finding", "inspect_endpoint", "refresh_evidence", "rerun_bounded_assessment", "review_authentication_context", "inspect_attack_surface", "investigate_regression", "update_baseline", "review_policy", "review_assessment_completion":
		return true
	default:
		return false
	}
}

func validActionPriority(priority string) bool {
	return priority == "high" || priority == "medium" || priority == "low"
}

func validAssessmentJSON(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 128<<10 && json.Valid([]byte(value)) && !secretLike(value)
}

func nullableAssessmentString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
