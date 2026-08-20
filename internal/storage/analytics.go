package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

type AnalyticsRequest struct {
	Window analytics.Window
	AsOf   time.Time
	Last   int
}

type AnalyticsSnapshotRecord struct {
	ProjectID, SnapshotFingerprint, SchemaVersion, SourceFingerprintsJSON, SnapshotJSON string
	Window                                                                              analytics.Window
	GeneratedAt                                                                         time.Time
}

// BuildAnalyticsSnapshot reads only project-local R18/R19/R20 state. Every
// selected record is revalidated before it reaches the pure analytics package.
func (db *DB) BuildAnalyticsSnapshot(ctx context.Context, projectID string, request AnalyticsRequest) (analytics.AnalyticsSnapshot, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) || request.AsOf.IsZero() {
		return analytics.AnalyticsSnapshot{}, errors.New("invalid analytics request")
	}
	evaluations, err := db.ListAssessmentEvaluations(ctx, projectID)
	if err != nil {
		return analytics.AnalyticsSnapshot{}, err
	}
	if request.Last < 0 || request.Last > analytics.MaxRecords {
		return analytics.AnalyticsSnapshot{}, errors.New("invalid analytics history limit")
	}
	if request.Last > 0 && len(evaluations) > request.Last {
		evaluations = evaluations[len(evaluations)-request.Last:]
	}
	comparisons, err := db.ListRegressionComparisons(ctx, projectID)
	if err != nil {
		return analytics.AnalyticsSnapshot{}, err
	}
	states, err := db.ListGovernanceRecommendationStates(ctx, projectID)
	if err != nil {
		return analytics.AnalyticsSnapshot{}, err
	}
	comparisonByFingerprint := make(map[string]RegressionComparisonRecord, len(comparisons))
	for _, comparison := range comparisons {
		if comparison.ProjectID != projectID || comparisonByFingerprint[comparison.Fingerprint].Fingerprint != "" {
			return analytics.AnalyticsSnapshot{}, errors.New("invalid duplicate or cross-project analytics comparison")
		}
		comparisonByFingerprint[comparison.Fingerprint] = comparison
	}
	statesByEvaluationAction := make(map[string]governance.RecommendationGovernanceState, len(states))
	for _, state := range states {
		if state.ProjectID != projectID || !governance.ValidateRecommendationState(state) {
			return analytics.AnalyticsSnapshot{}, errors.New("invalid persisted governance analytics state")
		}
		key := state.EvaluationFingerprint + "\x00" + state.RecommendationID
		if _, found := statesByEvaluationAction[key]; found {
			return analytics.AnalyticsSnapshot{}, errors.New("duplicate governance analytics state")
		}
		statesByEvaluationAction[key] = state
	}

	records := make([]analytics.HistoricalRecord, 0, minAnalyticsCount(len(evaluations), analytics.MaxRecords))
	exclusionReasons := []string{}
	excluded := 0
	for _, evaluation := range evaluations {
		record, include, reason := db.analyticsRecordForEvaluation(ctx, projectID, evaluation, comparisonByFingerprint, statesByEvaluationAction, request.Window)
		if !include {
			if reason != "outside_requested_window" {
				excluded++
				exclusionReasons = append(exclusionReasons, reason)
			}
			continue
		}
		if len(records) == analytics.MaxRecords {
			excluded++
			exclusionReasons = append(exclusionReasons, "analytics_record_limit_exceeded")
			continue
		}
		records = append(records, record)
	}
	if len(records) == 0 && excluded == 0 {
		excluded = 1
		exclusionReasons = append(exclusionReasons, "no_verified_assessment_history")
	}
	return analytics.BuildSnapshot(analytics.SnapshotInput{ProjectID: projectID, Window: request.Window, AsOf: request.AsOf, Records: records, ExcludedSourceCount: excluded, ExclusionReasons: exclusionReasons})
}

func (db *DB) analyticsRecordForEvaluation(ctx context.Context, projectID string, record AssessmentEvaluationRecord, comparisons map[string]RegressionComparisonRecord, states map[string]governance.RecommendationGovernanceState, window analytics.Window) (analytics.HistoricalRecord, bool, string) {
	var evaluation continuousassessment.ControlEvaluation
	if err := json.Unmarshal([]byte(record.EvaluationJSON), &evaluation); err != nil || !continuousassessment.ValidateControlEvaluation(evaluation) || record.ProjectID != projectID || evaluation.ProjectID != projectID || evaluation.Fingerprint != record.Fingerprint || evaluation.Fingerprint != record.EvaluationID || evaluation.PolicyFingerprint != record.PolicyID || evaluation.BaselineFingerprint != record.BaselineID || evaluation.BaselineSnapshot != record.BaselineSnapshotID || evaluation.CurrentSnapshot != record.CurrentSnapshotID || evaluation.ComparisonFingerprint != record.ComparisonID || evaluation.EvaluatedAt.UTC() != record.CreatedAt.UTC() {
		return analytics.HistoricalRecord{}, false, "invalid_r19_evaluation"
	}
	if evaluation.EvaluatedAt.Before(window.From) || evaluation.EvaluatedAt.After(window.To) {
		return analytics.HistoricalRecord{}, false, "outside_requested_window"
	}
	comparisonRecord, found := comparisons[evaluation.ComparisonFingerprint]
	if !found {
		return analytics.HistoricalRecord{}, false, "missing_r18_comparison"
	}
	comparison, baseline, current, err := db.canonicalAnalyticsComparison(ctx, projectID, comparisonRecord)
	if err != nil || comparison.Fingerprint != evaluation.ComparisonFingerprint || comparison.BaselineFingerprint != evaluation.BaselineSnapshot || comparison.CurrentFingerprint != evaluation.CurrentSnapshot {
		return analytics.HistoricalRecord{}, false, "invalid_r18_comparison"
	}
	actions, err := db.ListAssessmentActions(ctx, projectID, evaluation.Fingerprint)
	if err != nil {
		return analytics.HistoricalRecord{}, false, "invalid_r19_actions"
	}
	governanceCounts, actionFingerprints, err := db.analyticsGovernanceCounts(ctx, projectID, evaluation, actions, states)
	if err != nil {
		return analytics.HistoricalRecord{}, false, "invalid_r20_governance_lineage"
	}
	return analytics.HistoricalRecord{
		ProjectID:             projectID,
		Timestamp:             evaluation.EvaluatedAt.UTC(),
		SourceFingerprint:     analyticsSourceFingerprint(append([]string{evaluation.Fingerprint, comparison.Fingerprint, baseline.Fingerprint, current.Fingerprint}, actionFingerprints...)),
		SnapshotFingerprint:   current.Fingerprint,
		ComparisonFingerprint: comparison.Fingerprint,
		EvaluationFingerprint: evaluation.Fingerprint,
		RegressionCount:       analyticsRegressionCount(comparison),
		PolicyFailureCount:    boolToAnalyticsInt(evaluation.Summary.Failed > 0),
		Evidence:              analyticsEvidenceCounts(current),
		Surface:               analytics.SurfaceCounts{Endpoints: len(current.EndpointIDs), Parameters: len(current.ParameterIDs), CoverageDefinition: current.Coverage.Definition, CoverageNumerator: current.Coverage.Numerator, CoverageDenominator: current.Coverage.Denominator},
		Governance:            governanceCounts,
	}, true, ""
}

func (db *DB) canonicalAnalyticsComparison(ctx context.Context, projectID string, record RegressionComparisonRecord) (regression.Comparison, regression.Snapshot, regression.Snapshot, error) {
	if record.ProjectID != projectID || !validFingerprint(record.Fingerprint) || record.BaselineSnapshotID == record.CurrentSnapshotID {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, errors.New("invalid analytics regression comparison record")
	}
	baselineRecord, err := db.LoadRegressionSnapshot(ctx, projectID, record.BaselineSnapshotID)
	if err != nil {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, err
	}
	currentRecord, err := db.LoadRegressionSnapshot(ctx, projectID, record.CurrentSnapshotID)
	if err != nil {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, err
	}
	baseline, err := canonicalAnalyticsSnapshot(baselineRecord, projectID)
	if err != nil {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, err
	}
	current, err := canonicalAnalyticsSnapshot(currentRecord, projectID)
	if err != nil {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, err
	}
	var stored regression.Comparison
	if err := json.Unmarshal([]byte(record.ComparisonJSON), &stored); err != nil || stored.ProjectID != projectID || stored.Fingerprint != record.Fingerprint || stored.BaselineFingerprint != baseline.Fingerprint || stored.CurrentFingerprint != current.Fingerprint {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, errors.New("invalid stored analytics comparison")
	}
	canonical, err := regression.Compare(baseline, current)
	if err != nil || canonical.Fingerprint != stored.Fingerprint || !equalAnalyticsJSON(canonical, stored) {
		return regression.Comparison{}, regression.Snapshot{}, regression.Snapshot{}, errors.New("analytics comparison integrity mismatch")
	}
	return canonical, baseline, current, nil
}

func canonicalAnalyticsSnapshot(record RegressionSnapshotRecord, projectID string) (regression.Snapshot, error) {
	var stored regression.Snapshot
	if err := json.Unmarshal([]byte(record.SnapshotJSON), &stored); err != nil || record.ProjectID != projectID || stored.ProjectID != projectID || stored.Fingerprint != record.SnapshotFingerprint || stored.Fingerprint != record.SnapshotID || stored.CreatedAt.UTC() != record.CreatedAt.UTC() {
		return regression.Snapshot{}, errors.New("invalid stored analytics snapshot")
	}
	canonical, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: stored.ProjectID, CampaignID: stored.CampaignID, ScopeVersion: stored.ScopeVersion, AssessmentID: stored.AssessmentID, SurfaceSnapshotID: stored.SurfaceSnapshotID, SchemaVersion: stored.SchemaVersion, CreatedAt: stored.CreatedAt, EndpointIDs: stored.EndpointIDs, ParameterIDs: stored.ParameterIDs, Findings: stored.Findings, Evidence: stored.Evidence, Coverage: stored.Coverage})
	if err != nil || canonical.Fingerprint != stored.Fingerprint || !equalAnalyticsJSON(canonical, stored) {
		return regression.Snapshot{}, errors.New("analytics snapshot integrity mismatch")
	}
	return canonical, nil
}

func (db *DB) analyticsGovernanceCounts(ctx context.Context, projectID string, evaluation continuousassessment.ControlEvaluation, actions []AssessmentActionRecord, states map[string]governance.RecommendationGovernanceState) (analytics.GovernanceCounts, []string, error) {
	counts := analytics.GovernanceCounts{}
	fingerprints := make([]string, 0, len(actions))
	canonicalActions := make(map[string]continuousassessment.AssessmentAction, len(evaluation.Actions))
	for _, action := range evaluation.Actions {
		canonicalActions[action.ID] = action
	}
	for _, actionRecord := range actions {
		loaded, err := db.LoadAssessmentAction(ctx, projectID, actionRecord.ActionID)
		if err != nil {
			return analytics.GovernanceCounts{}, nil, err
		}
		var stored continuousassessment.AssessmentAction
		if err := json.Unmarshal([]byte(loaded.ActionJSON), &stored); err != nil || stored != canonicalActions[loaded.ActionID] || loaded.EvaluationID != evaluation.Fingerprint || loaded.Fingerprint != loaded.ActionID {
			return analytics.GovernanceCounts{}, nil, errors.New("invalid analytics assessment action")
		}
		state := governance.RecommendationRecommended
		fingerprints = append(fingerprints, loaded.ActionID)
		if persisted, found := states[evaluation.Fingerprint+"\x00"+loaded.ActionID]; found {
			if persisted.ProjectID != projectID || persisted.PolicyFingerprint != evaluation.PolicyFingerprint || persisted.BaselineFingerprint != evaluation.BaselineFingerprint || persisted.RecommendationFingerprint != loaded.ActionID {
				return analytics.GovernanceCounts{}, nil, errors.New("invalid analytics governance state linkage")
			}
			state = persisted.State
			fingerprints = append(fingerprints, persisted.Fingerprint)
		}
		switch state {
		case governance.RecommendationRecommended:
			counts.Recommended++
			counts.Unresolved++
		case governance.RecommendationAcknowledged:
			counts.Acknowledged++
			counts.Unresolved++
		case governance.RecommendationAccepted:
			counts.Accepted++
			counts.Unresolved++
		case governance.RecommendationDeferred:
			counts.Deferred++
			counts.Unresolved++
		case governance.RecommendationRejected:
			counts.Rejected++
		case governance.RecommendationCompleted:
			counts.Completed++
		case governance.RecommendationExpired:
			counts.Expired++
		default:
			return analytics.GovernanceCounts{}, nil, errors.New("invalid analytics governance lifecycle")
		}
	}
	sort.Strings(fingerprints)
	return counts, fingerprints, nil
}

func analyticsRegressionCount(comparison regression.Comparison) int {
	count := 0
	for _, item := range comparison.Items {
		if item.Change == regression.ChangeNewFinding || item.Change == regression.ChangeRiskIncreased || item.Change == regression.ChangeEvidenceStale || item.Change == regression.ChangeEvidenceContradiction || item.Change == regression.ChangeCoverageDecreased {
			count++
		}
	}
	return count
}

func analyticsEvidenceCounts(snapshot regression.Snapshot) analytics.EvidenceCounts {
	counts := analytics.EvidenceCounts{}
	for _, evidence := range snapshot.Evidence {
		switch evidence.Freshness {
		case "fresh":
			counts.Fresh++
		case "stale":
			counts.Stale++
		}
		switch evidence.Verification {
		case "unsupported":
			counts.Unsupported++
		case "incomplete":
			counts.Incomplete++
		}
		if len(evidence.Contradictions) > 0 {
			counts.Contradictory++
		}
		if evidence.Reproducibility == "reproducible" {
			counts.Reproducible++
		}
	}
	return counts
}

func analyticsSourceFingerprint(values []string) string {
	sort.Strings(values)
	encoded, _ := json.Marshal(values)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func equalAnalyticsJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func boolToAnalyticsInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func minAnalyticsCount(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// SaveAnalyticsSnapshot stores only canonical, bounded derived data. Source
// records remain read-only and an identical deterministic replay is idempotent.
func (db *DB) SaveAnalyticsSnapshot(ctx context.Context, snapshot analytics.AnalyticsSnapshot) error {
	if db == nil || db.sql == nil || !analytics.ValidateSnapshot(snapshot) {
		return errors.New("invalid analytics snapshot")
	}
	sourcesJSON, err := json.Marshal(snapshot.SourceFingerprints)
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil || len(sourcesJSON) > 64<<10 || len(snapshotJSON) > 256<<10 {
		return errors.New("invalid analytics snapshot serialization")
	}
	result, err := db.sql.ExecContext(ctx, `INSERT INTO analytics_snapshots(project_id,snapshot_fingerprint,schema_version,window_from,window_to,generated_at,source_fingerprints_json,snapshot_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project_id,snapshot_fingerprint) DO NOTHING`, snapshot.ProjectID, snapshot.Fingerprint, snapshot.SchemaVersion, formatStorageTime(snapshot.Window.From), formatStorageTime(snapshot.Window.To), formatStorageTime(snapshot.GeneratedAt), string(sourcesJSON), string(snapshotJSON))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return nil
	}
	var stored string
	if err := db.sql.QueryRowContext(ctx, `SELECT snapshot_json FROM analytics_snapshots WHERE project_id=? AND snapshot_fingerprint=?`, snapshot.ProjectID, snapshot.Fingerprint).Scan(&stored); err != nil {
		return err
	}
	if stored != string(snapshotJSON) {
		return errors.New("conflicting immutable analytics snapshot")
	}
	return nil
}

// LoadVerifiedAnalyticsSnapshot returns a cache only when a fresh canonical
// reconstruction from the selected source state has the same snapshot identity.
func (db *DB) LoadVerifiedAnalyticsSnapshot(ctx context.Context, projectID string, request AnalyticsRequest) (analytics.AnalyticsSnapshot, bool, error) {
	expected, err := db.BuildAnalyticsSnapshot(ctx, projectID, request)
	if err != nil {
		return analytics.AnalyticsSnapshot{}, false, err
	}
	var stored string
	err = db.sql.QueryRowContext(ctx, `SELECT snapshot_json FROM analytics_snapshots WHERE project_id=? AND snapshot_fingerprint=? AND schema_version=?`, projectID, expected.Fingerprint, analytics.SchemaVersion).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return analytics.AnalyticsSnapshot{}, false, nil
	}
	if err != nil {
		return analytics.AnalyticsSnapshot{}, false, err
	}
	var cached analytics.AnalyticsSnapshot
	if err := json.Unmarshal([]byte(stored), &cached); err != nil || !analytics.ValidateSnapshot(cached) || !equalAnalyticsJSON(cached, expected) {
		return analytics.AnalyticsSnapshot{}, false, errors.New("invalid or stale analytics snapshot cache")
	}
	return cached, true, nil
}

func analyticsSafeReason(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "invalid_analytics_source"
	}
	return value
}
