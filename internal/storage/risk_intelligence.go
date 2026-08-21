package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

type SecurityFindingRecord struct {
	FindingID, ProjectID, RunID, ValidationID, CorrelationID string
	EndpointID, ParameterID, AssetID, Class, Subtype         string
	Title, Description, RemediationHint                      string
	Confidence, Severity                                     string
	RiskScore                                                int
	RiskBand, RiskModelVersion, RiskReason, Status           string
	RiskFactorsJSON                                          string
	FirstSeenAt, LastSeenAt, ValidatedAt, RiskCalculatedAt   time.Time
	Fingerprint                                              string
	EvidenceReferences                                       []string
}

type SecurityFindingFilter struct {
	Severity, Status, Class string
	MinRisk                 int
	AssetID                 string
	Limit                   int
}

type FindingHistoryRecord struct {
	FindingID, ProjectID, Event, Reason, CreatedBy string
	At                                             time.Time
}

type FindingSuppressionRecord struct {
	ProjectID, Fingerprint, Reason, CreatedBy string
	CreatedAt, ExpiresAt                      time.Time
}

func (db *DB) UpsertSecurityFinding(ctx context.Context, finding SecurityFindingRecord) error {
	if db == nil || db.sql == nil || !validSecurityFinding(finding) {
		return errors.New("invalid security finding")
	}
	factors := finding.RiskFactorsJSON
	if !json.Valid([]byte(factors)) {
		return errors.New("invalid risk factor JSON")
	}
	evidenceRefs, err := json.Marshal(finding.EvidenceReferences)
	if err != nil {
		return fmt.Errorf("encode evidence references: %w", err)
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO security_findings(project_id, finding_id, run_id, validation_id, correlation_id, endpoint_id, parameter_id, asset_id, class, subtype, title, description, remediation_hint, confidence, severity, risk_score, risk_band, risk_model_version, risk_factors_json, risk_reason, status, first_seen_at, last_seen_at, validated_at, fingerprint, evidence_refs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id, finding_id) DO UPDATE SET run_id=excluded.run_id, validation_id=excluded.validation_id, correlation_id=excluded.correlation_id, endpoint_id=excluded.endpoint_id, parameter_id=excluded.parameter_id, asset_id=excluded.asset_id, class=excluded.class, subtype=excluded.subtype, title=excluded.title, description=excluded.description, remediation_hint=excluded.remediation_hint, confidence=excluded.confidence, severity=excluded.severity, risk_score=excluded.risk_score, risk_band=excluded.risk_band, risk_model_version=excluded.risk_model_version, risk_factors_json=excluded.risk_factors_json, risk_reason=excluded.risk_reason, status=excluded.status, last_seen_at=excluded.last_seen_at, validated_at=excluded.validated_at, evidence_refs_json=excluded.evidence_refs_json`, finding.ProjectID, finding.FindingID, finding.RunID, finding.ValidationID, finding.CorrelationID, finding.EndpointID, finding.ParameterID, finding.AssetID, finding.Class, finding.Subtype, finding.Title, finding.Description, finding.RemediationHint, finding.Confidence, finding.Severity, finding.RiskScore, finding.RiskBand, finding.RiskModelVersion, factors, finding.RiskReason, finding.Status, formatStorageTime(finding.FirstSeenAt), formatStorageTime(finding.LastSeenAt), formatStorageTime(finding.ValidatedAt), finding.Fingerprint, string(evidenceRefs))
	if err != nil {
		return fmt.Errorf("upsert security finding: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO risk_assessments(project_id, finding_id, model_version, score, band, factors_json, reason, calculated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project_id, finding_id, model_version) DO UPDATE SET score=excluded.score, band=excluded.band, factors_json=excluded.factors_json, reason=excluded.reason, calculated_at=excluded.calculated_at`, finding.ProjectID, finding.FindingID, finding.RiskModelVersion, finding.RiskScore, finding.RiskBand, factors, finding.RiskReason, formatStorageTime(finding.RiskCalculatedAt))
	if err != nil {
		return fmt.Errorf("upsert risk assessment: %w", err)
	}
	return tx.Commit()
}

func (db *DB) AppendFindingHistory(ctx context.Context, history FindingHistoryRecord) error {
	if db == nil || db.sql == nil || strings.TrimSpace(history.ProjectID) == "" || strings.TrimSpace(history.FindingID) == "" || strings.TrimSpace(history.Event) == "" || history.At.IsZero() {
		return errors.New("invalid finding history")
	}
	result, err := db.sql.ExecContext(ctx, `INSERT INTO finding_history(project_id, event_id, finding_id, event, reason, created_by, occurred_at) VALUES(?,?,?,?,?,?,?)`, history.ProjectID, historyID(history), history.FindingID, history.Event, history.Reason, history.CreatedBy, formatStorageTime(history.At))
	if err != nil {
		return fmt.Errorf("append finding history: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return errors.New("finding history was not appended")
	}
	return nil
}

func (db *DB) UpsertFindingSuppression(ctx context.Context, suppression FindingSuppressionRecord) error {
	if db == nil || db.sql == nil || strings.TrimSpace(suppression.ProjectID) == "" || strings.TrimSpace(suppression.Fingerprint) == "" || strings.TrimSpace(suppression.Reason) == "" || suppression.CreatedAt.IsZero() || (!suppression.ExpiresAt.IsZero() && !suppression.ExpiresAt.After(suppression.CreatedAt)) {
		return errors.New("invalid finding suppression")
	}
	var exists int
	if err := db.sql.QueryRowContext(ctx, `SELECT 1 FROM security_findings WHERE project_id=? AND fingerprint=?`, suppression.ProjectID, suppression.Fingerprint).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("suppression finding is absent from the selected project")
		}
		return err
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO finding_suppressions(project_id, fingerprint, reason, created_by, created_at, expires_at) VALUES(?,?,?,?,?,?) ON CONFLICT(project_id, fingerprint) DO UPDATE SET reason=excluded.reason, created_by=excluded.created_by, created_at=excluded.created_at, expires_at=excluded.expires_at`, suppression.ProjectID, suppression.Fingerprint, suppression.Reason, suppression.CreatedBy, formatStorageTime(suppression.CreatedAt), nullableStorageTime(suppression.ExpiresAt))
	return err
}

func (db *DB) ListSecurityFindings(ctx context.Context, projectID string, filter SecurityFindingFilter) ([]SecurityFindingRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" || filter.MinRisk < 0 || filter.MinRisk > 100 || (filter.Limit != 0 && (filter.Limit < 1 || filter.Limit > 500)) {
		return nil, errors.New("invalid security finding query")
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	where, args := []string{"project_id=?"}, []any{projectID}
	if filter.Severity != "" {
		where, args = append(where, "severity=?"), append(args, filter.Severity)
	}
	if filter.Status != "" {
		where, args = append(where, "status=?"), append(args, filter.Status)
	}
	if filter.Class != "" {
		where, args = append(where, "class=?"), append(args, filter.Class)
	}
	if filter.MinRisk > 0 {
		where, args = append(where, "risk_score>=?"), append(args, filter.MinRisk)
	}
	if strings.TrimSpace(filter.AssetID) != "" {
		where, args = append(where, "asset_id=?"), append(args, strings.TrimSpace(filter.AssetID))
	}
	args = append(args, limit)
	query := `SELECT finding_id, project_id, run_id, validation_id, correlation_id, endpoint_id, parameter_id, asset_id, class, subtype, title, description, remediation_hint, confidence, severity, risk_score, risk_band, risk_model_version, risk_factors_json, risk_reason, status, first_seen_at, last_seen_at, validated_at, fingerprint, evidence_refs_json FROM security_findings WHERE ` + strings.Join(where, " AND ") + ` ORDER BY risk_score DESC, CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, finding_id ASC LIMIT ?`
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := make([]SecurityFindingRecord, 0)
	for rows.Next() {
		finding, err := scanSecurityFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

type securityFindingRow interface{ Scan(...any) error }

func scanSecurityFinding(row securityFindingRow) (SecurityFindingRecord, error) {
	var finding SecurityFindingRecord
	var firstSeen, lastSeen, validatedAt, evidenceJSON string
	if err := row.Scan(&finding.FindingID, &finding.ProjectID, &finding.RunID, &finding.ValidationID, &finding.CorrelationID, &finding.EndpointID, &finding.ParameterID, &finding.AssetID, &finding.Class, &finding.Subtype, &finding.Title, &finding.Description, &finding.RemediationHint, &finding.Confidence, &finding.Severity, &finding.RiskScore, &finding.RiskBand, &finding.RiskModelVersion, &finding.RiskFactorsJSON, &finding.RiskReason, &finding.Status, &firstSeen, &lastSeen, &validatedAt, &finding.Fingerprint, &evidenceJSON); err != nil {
		return SecurityFindingRecord{}, err
	}
	var err error
	if finding.FirstSeenAt, err = parseStorageTime(firstSeen); err != nil {
		return SecurityFindingRecord{}, err
	}
	if finding.LastSeenAt, err = parseStorageTime(lastSeen); err != nil {
		return SecurityFindingRecord{}, err
	}
	if finding.ValidatedAt, err = parseStorageTime(validatedAt); err != nil {
		return SecurityFindingRecord{}, err
	}
	finding.RiskCalculatedAt = finding.ValidatedAt
	if err := json.Unmarshal([]byte(evidenceJSON), &finding.EvidenceReferences); err != nil {
		return SecurityFindingRecord{}, err
	}
	return finding, nil
}

func validSecurityFinding(finding SecurityFindingRecord) bool {
	return strings.TrimSpace(finding.ProjectID) != "" && strings.TrimSpace(finding.FindingID) != "" && strings.TrimSpace(finding.ValidationID) != "" && strings.TrimSpace(finding.CorrelationID) != "" && strings.TrimSpace(finding.EndpointID) != "" && strings.TrimSpace(finding.ParameterID) != "" && strings.TrimSpace(finding.Fingerprint) != "" && finding.RiskScore >= 0 && finding.RiskScore <= 100 && strings.TrimSpace(finding.RiskModelVersion) != "" && !finding.RiskCalculatedAt.IsZero() && !finding.FirstSeenAt.IsZero() && !finding.LastSeenAt.IsZero() && !finding.ValidatedAt.IsZero() && safeEvidenceReferences(finding.EvidenceReferences) && safeFindingFields(finding) && safeFindingFactors(finding.RiskFactorsJSON)
}

func safeEvidenceReferences(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value = strings.TrimSpace(value); value == "" || dataclassification.ValidateSafeReference(value) != nil {
			return false
		}
	}
	return true
}
func secretLike(value string) bool {
	return dataclassification.IsSecretLike(value)
}

func safeFindingFields(finding SecurityFindingRecord) bool {
	for _, value := range []string{finding.ProjectID, finding.FindingID, finding.RunID, finding.ValidationID, finding.CorrelationID, finding.EndpointID, finding.ParameterID, finding.AssetID, finding.Class, finding.Subtype, finding.Title, finding.Description, finding.RemediationHint, finding.Confidence, finding.Severity, finding.RiskBand, finding.RiskModelVersion, finding.RiskReason, finding.Status, finding.Fingerprint} {
		if strings.TrimSpace(value) != "" && dataclassification.ValidateSafeText(value, 4096) != nil {
			return false
		}
	}
	return true
}

func safeFindingFactors(raw string) bool {
	if !json.Valid([]byte(raw)) {
		return false
	}
	_, decision, err := dataclassification.SanitizeJSON([]byte(raw), dataclassification.DefaultLimits())
	return err == nil && !decision.Redacted
}
func historyID(history FindingHistoryRecord) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{history.ProjectID, history.FindingID, history.Event, history.Reason, history.CreatedBy, formatStorageTime(history.At)}, "\x00")))
	return hex.EncodeToString(sum[:])
}
func formatStorageTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func nullableStorageTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return formatStorageTime(value)
}
func parseStorageTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }
