package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

var (
	ErrDataGovernancePolicyExists   = errors.New("data governance policy already exists")
	ErrDataGovernancePolicyNotFound = errors.New("data governance policy not found")
	ErrDataRetentionRecordExists    = errors.New("data retention record already exists")
)

// SaveDataGovernancePolicy persists a policy only after canonical integrity
// validation. It never accepts raw secret-bearing identifiers or policy data.
func (db *DB) SaveDataGovernancePolicy(ctx context.Context, policy datagovernance.Policy) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := datagovernance.ValidatePolicy(policy); err != nil {
		return err
	}
	rules, err := encodeGovernanceRules(policy.Rules)
	if err != nil {
		return err
	}
	var expiresAt any
	if !policy.ExpiresAt.IsZero() {
		expiresAt = policy.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO data_governance_policies(project_id, version, policy_version, canonical_rules, created_at, expires_at, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?)`, policy.ProjectID, policy.Version, policy.PolicyVersion, rules, policy.CreatedAt.UTC().Format(time.RFC3339Nano), expiresAt, policy.Fingerprint)
	if err != nil {
		if isConstraintError(err) {
			return ErrDataGovernancePolicyExists
		}
		return fmt.Errorf("save data governance policy: %w", err)
	}
	return nil
}

// LoadDataGovernancePolicy always recomputes the canonical policy fingerprint
// after hydration and scopes the query by the caller's project.
func (db *DB) LoadDataGovernancePolicy(ctx context.Context, projectID, version string) (datagovernance.Policy, error) {
	if db == nil || db.sql == nil {
		return datagovernance.Policy{}, errors.New("storage database is not initialized")
	}
	if dataclassification.ValidateSafeText(projectID, 256) != nil || dataclassification.ValidateSafeText(version, 256) != nil {
		return datagovernance.Policy{}, datagovernance.ErrPolicyInvalid
	}
	var policy datagovernance.Policy
	var rulesJSON, createdAt, expiresAt string
	err := db.sql.QueryRowContext(ctx, `SELECT project_id, version, policy_version, canonical_rules, created_at, COALESCE(expires_at, ''), fingerprint FROM data_governance_policies WHERE project_id = ? AND version = ?`, strings.TrimSpace(projectID), strings.TrimSpace(version)).Scan(&policy.ProjectID, &policy.Version, &policy.PolicyVersion, &rulesJSON, &createdAt, &expiresAt, &policy.Fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return datagovernance.Policy{}, ErrDataGovernancePolicyNotFound
	}
	if err != nil {
		return datagovernance.Policy{}, fmt.Errorf("load data governance policy: %w", err)
	}
	var parseErr error
	policy.Rules, parseErr = decodeGovernanceRules(rulesJSON)
	if parseErr != nil {
		return datagovernance.Policy{}, datagovernance.ErrGovernanceIntegrityFailure
	}
	policy.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdAt)
	if parseErr != nil {
		return datagovernance.Policy{}, datagovernance.ErrGovernanceIntegrityFailure
	}
	if expiresAt != "" {
		policy.ExpiresAt, parseErr = time.Parse(time.RFC3339Nano, expiresAt)
		if parseErr != nil {
			return datagovernance.Policy{}, datagovernance.ErrGovernanceIntegrityFailure
		}
	}
	if err := datagovernance.ValidatePolicy(policy); err != nil {
		return datagovernance.Policy{}, err
	}
	return policy, nil
}

// ListDataGovernancePolicies returns only policies belonging to the requested
// project. Each row is loaded through the canonical validation path.
func (db *DB) ListDataGovernancePolicies(ctx context.Context, projectID string) ([]datagovernance.Policy, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if dataclassification.ValidateSafeText(projectID, 256) != nil {
		return nil, datagovernance.ErrPolicyInvalid
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT version FROM data_governance_policies WHERE project_id = ? ORDER BY created_at, version`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, fmt.Errorf("list data governance policies: %w", err)
	}
	defer rows.Close()
	policies := make([]datagovernance.Policy, 0)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan data governance policy version: %w", err)
		}
		policy, err := db.LoadDataGovernancePolicy(ctx, strings.TrimSpace(projectID), version)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

func (db *DB) SaveDataRetentionRecord(ctx context.Context, record datagovernance.RetentionRecord) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := datagovernance.ValidateRetentionRecord(record); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO data_retention_records(project_id, policy_version, policy_fingerprint, subject_reference, created_at, retain_until, hold, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, record.ProjectID, record.PolicyVersion, record.PolicyFingerprint, record.SubjectReference, record.CreatedAt.UTC().Format(time.RFC3339Nano), record.RetainUntil.UTC().Format(time.RFC3339Nano), boolToInt(record.Hold), record.Fingerprint)
	if err != nil {
		if isConstraintError(err) {
			return ErrDataRetentionRecordExists
		}
		return fmt.Errorf("save data retention record: %w", err)
	}
	return nil
}

func (db *DB) ListDataRetentionRecords(ctx context.Context, projectID string) ([]datagovernance.RetentionRecord, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if dataclassification.ValidateSafeText(projectID, 256) != nil {
		return nil, datagovernance.ErrRetentionViolation
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, policy_version, policy_fingerprint, subject_reference, created_at, retain_until, hold, fingerprint FROM data_retention_records WHERE project_id = ? ORDER BY retain_until, fingerprint`, strings.TrimSpace(projectID))
	if err != nil {
		return nil, fmt.Errorf("list data retention records: %w", err)
	}
	defer rows.Close()
	records := make([]datagovernance.RetentionRecord, 0)
	for rows.Next() {
		var record datagovernance.RetentionRecord
		var createdAt, retainUntil string
		var hold int
		if err := rows.Scan(&record.ProjectID, &record.PolicyVersion, &record.PolicyFingerprint, &record.SubjectReference, &createdAt, &retainUntil, &hold, &record.Fingerprint); err != nil {
			return nil, fmt.Errorf("scan data retention record: %w", err)
		}
		var parseErr error
		record.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdAt)
		if parseErr == nil {
			record.RetainUntil, parseErr = time.Parse(time.RFC3339Nano, retainUntil)
		}
		if parseErr != nil || (hold != 0 && hold != 1) {
			return nil, datagovernance.ErrGovernanceIntegrityFailure
		}
		record.Hold = hold == 1
		if err := datagovernance.ValidateRetentionRecord(record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func encodeGovernanceRules(rules []datagovernance.Rule) (string, error) {
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", datagovernance.ErrGovernanceIntegrityFailure
	}
	return string(encoded), nil
}

func decodeGovernanceRules(raw string) ([]datagovernance.Rule, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var rules []datagovernance.Rule
	if err := decoder.Decode(&rules); err != nil || decoder.More() || len(rules) == 0 {
		return nil, datagovernance.ErrGovernanceIntegrityFailure
	}
	return rules, nil
}

func isConstraintError(err error) bool {
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "constraint") || strings.Contains(value, "unique")
}
