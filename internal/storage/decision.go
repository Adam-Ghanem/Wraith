package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/decisionintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

type DecisionRequest struct {
	Analytics AnalyticsRequest
}

type DecisionSnapshotRecord struct {
	ProjectID, SnapshotFingerprint, SchemaVersion, DecisionVersion, SourceFingerprintsJSON, SnapshotJSON string
	GeneratedAt                                                                                          time.Time
}

// BuildDecisionSnapshot reads only freshly revalidated, project-local R18–R21
// material. The pure decision package receives no database handle or raw data.
func (db *DB) BuildDecisionSnapshot(ctx context.Context, projectID string, request DecisionRequest) (decisionintelligence.DecisionSnapshot, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) || request.Analytics.AsOf.IsZero() {
		return decisionintelligence.DecisionSnapshot{}, errors.New("invalid decision request")
	}
	analyticsSnapshot, err := db.BuildAnalyticsSnapshot(ctx, projectID, request.Analytics)
	if err != nil || !analytics.ValidateSnapshot(analyticsSnapshot) || analyticsSnapshot.DataQuality.ValidRecordCount == 0 {
		return decisionintelligence.DecisionSnapshot{}, errors.New("no validated analytics source for decision")
	}
	evaluationRecord, evaluation, err := db.latestCanonicalDecisionEvaluation(ctx, projectID, request.Analytics)
	if err != nil {
		return decisionintelligence.DecisionSnapshot{}, err
	}
	policy, err := db.canonicalDecisionPolicy(ctx, projectID, evaluationRecord.PolicyID)
	if err != nil || policy.Fingerprint != evaluation.PolicyFingerprint {
		return decisionintelligence.DecisionSnapshot{}, errors.New("invalid r19 policy lineage for decision")
	}
	baseline, err := db.canonicalDecisionBaseline(ctx, projectID, evaluationRecord.BaselineID)
	if err != nil || baseline.Fingerprint != evaluation.BaselineFingerprint || baseline.PolicyFingerprint != policy.Fingerprint {
		return decisionintelligence.DecisionSnapshot{}, errors.New("invalid r19 baseline lineage for decision")
	}
	comparisonRecord, err := db.decisionComparisonRecord(ctx, projectID, evaluation.ComparisonFingerprint)
	if err != nil {
		return decisionintelligence.DecisionSnapshot{}, err
	}
	comparison, baselineSnapshot, currentSnapshot, err := db.canonicalAnalyticsComparison(ctx, projectID, comparisonRecord)
	if err != nil || comparison.Fingerprint != evaluation.ComparisonFingerprint || baselineSnapshot.Fingerprint != evaluation.BaselineSnapshot || currentSnapshot.Fingerprint != evaluation.CurrentSnapshot || baseline.SnapshotFingerprint != baselineSnapshot.Fingerprint {
		return decisionintelligence.DecisionSnapshot{}, errors.New("invalid r18 comparison lineage for decision")
	}
	status, err := db.canonicalDecisionGovernanceStatus(ctx, projectID, evaluation, request.Analytics.AsOf)
	if err != nil {
		return decisionintelligence.DecisionSnapshot{}, err
	}
	input := decisionintelligence.Input{
		ProjectID:   projectID,
		GeneratedAt: request.Analytics.AsOf.UTC(),
		Analytics:   analyticsSnapshot,
		Lineage: decisionintelligence.DecisionLineage{
			ProjectID:             projectID,
			AnalyticsFingerprint:  analyticsSnapshot.Fingerprint,
			ComparisonFingerprint: comparison.Fingerprint,
			EvaluationFingerprint: evaluation.Fingerprint,
			PolicyFingerprint:     policy.Fingerprint,
			GovernanceFingerprint: status.Fingerprint,
		},
		Policy:            decisionintelligence.PolicyState{Fingerprint: policy.Fingerprint, Status: evaluationRecord.Status, FailedRules: evaluation.Summary.Failed},
		Governance:        decisionintelligence.GovernanceState{Fingerprint: status.Fingerprint, Overall: string(status.Overall), Unresolved: status.UnresolvedCount},
		RegressionSignals: decisionRegressionSignals(comparison),
	}
	return decisionintelligence.Evaluate(input)
}

func (db *DB) latestCanonicalDecisionEvaluation(ctx context.Context, projectID string, request AnalyticsRequest) (AssessmentEvaluationRecord, continuousassessment.ControlEvaluation, error) {
	evaluations, err := db.ListAssessmentEvaluations(ctx, projectID)
	if err != nil {
		return AssessmentEvaluationRecord{}, continuousassessment.ControlEvaluation{}, err
	}
	var latest AssessmentEvaluationRecord
	var canonical continuousassessment.ControlEvaluation
	found := false
	for _, record := range evaluations {
		if record.CreatedAt.Before(request.Window.From) || record.CreatedAt.After(request.Window.To) {
			continue
		}
		var evaluation continuousassessment.ControlEvaluation
		if err := json.Unmarshal([]byte(record.EvaluationJSON), &evaluation); err != nil || !continuousassessment.ValidateControlEvaluation(evaluation) || record.ProjectID != projectID || evaluation.ProjectID != projectID || record.EvaluationID != evaluation.Fingerprint || record.Fingerprint != evaluation.Fingerprint || record.PolicyID != evaluation.PolicyFingerprint || record.BaselineID != evaluation.BaselineFingerprint || record.BaselineSnapshotID != evaluation.BaselineSnapshot || record.CurrentSnapshotID != evaluation.CurrentSnapshot || record.ComparisonID != evaluation.ComparisonFingerprint || record.CreatedAt.UTC() != evaluation.EvaluatedAt.UTC() {
			continue
		}
		if !found || latest.CreatedAt.Before(record.CreatedAt) || (latest.CreatedAt.Equal(record.CreatedAt) && latest.EvaluationID < record.EvaluationID) {
			latest, canonical, found = record, evaluation, true
		}
	}
	if !found {
		return AssessmentEvaluationRecord{}, continuousassessment.ControlEvaluation{}, errors.New("no canonical evaluation in selected decision window")
	}
	return latest, canonical, nil
}

func (db *DB) canonicalDecisionPolicy(ctx context.Context, projectID, policyID string) (continuousassessment.AssessmentPolicy, error) {
	record, err := db.LoadAssessmentPolicy(ctx, projectID, policyID)
	if err != nil {
		return continuousassessment.AssessmentPolicy{}, err
	}
	var stored continuousassessment.AssessmentPolicy
	if err := json.Unmarshal([]byte(record.PolicyJSON), &stored); err != nil || record.ProjectID != projectID || stored.ProjectID != projectID || stored.Fingerprint != record.PolicyID || stored.Fingerprint != record.Fingerprint || stored.Name != record.Name || stored.Version != record.Version {
		return continuousassessment.AssessmentPolicy{}, errors.New("invalid stored decision policy")
	}
	canonical, err := continuousassessment.NewPolicy(continuousassessment.PolicyInput{ProjectID: stored.ProjectID, Name: stored.Name, Version: stored.Version, Rules: stored.Rules})
	if err != nil || !equalAnalyticsJSON(canonical, stored) {
		return continuousassessment.AssessmentPolicy{}, errors.New("decision policy integrity mismatch")
	}
	return canonical, nil
}

func (db *DB) canonicalDecisionBaseline(ctx context.Context, projectID, baselineID string) (continuousassessment.AssessmentBaseline, error) {
	record, err := db.LoadAssessmentBaseline(ctx, projectID, baselineID)
	if err != nil {
		return continuousassessment.AssessmentBaseline{}, err
	}
	var stored continuousassessment.AssessmentBaseline
	if err := json.Unmarshal([]byte(record.BaselineJSON), &stored); err != nil || record.ProjectID != projectID || stored.ProjectID != projectID || stored.Fingerprint != record.BaselineID || stored.Fingerprint != record.Fingerprint || stored.SnapshotFingerprint != record.SnapshotID || stored.PolicyFingerprint != record.PolicyID || stored.CampaignID != record.CampaignID || stored.CreatedAt.UTC() != record.CreatedAt.UTC() {
		return continuousassessment.AssessmentBaseline{}, errors.New("invalid stored decision baseline")
	}
	canonical, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: stored.ProjectID, SnapshotFingerprint: stored.SnapshotFingerprint, SnapshotCreatedAt: stored.SnapshotCreatedAt, PolicyFingerprint: stored.PolicyFingerprint, CampaignID: stored.CampaignID, Description: stored.Description, CreatedAt: stored.CreatedAt})
	if err != nil || !equalAnalyticsJSON(canonical, stored) {
		return continuousassessment.AssessmentBaseline{}, errors.New("decision baseline integrity mismatch")
	}
	return canonical, nil
}

func (db *DB) decisionComparisonRecord(ctx context.Context, projectID, fingerprint string) (RegressionComparisonRecord, error) {
	comparisons, err := db.ListRegressionComparisons(ctx, projectID)
	if err != nil {
		return RegressionComparisonRecord{}, err
	}
	for _, comparison := range comparisons {
		if comparison.Fingerprint == fingerprint {
			return comparison, nil
		}
	}
	return RegressionComparisonRecord{}, errors.New("decision comparison absent from selected project")
}

func (db *DB) canonicalDecisionGovernanceStatus(ctx context.Context, projectID string, evaluation continuousassessment.ControlEvaluation, asOf time.Time) (governance.GovernanceStatus, error) {
	states, err := db.ListGovernanceRecommendationStates(ctx, projectID)
	if err != nil {
		return governance.GovernanceStatus{}, err
	}
	valid := make([]governance.RecommendationGovernanceState, 0)
	for _, state := range states {
		if state.ProjectID != projectID || !governance.ValidateRecommendationState(state) {
			return governance.GovernanceStatus{}, errors.New("invalid governance source for decision")
		}
		if state.EvaluationFingerprint == evaluation.Fingerprint {
			if state.PolicyFingerprint != evaluation.PolicyFingerprint || state.BaselineFingerprint != evaluation.BaselineFingerprint {
				return governance.GovernanceStatus{}, errors.New("invalid governance decision lineage")
			}
			valid = append(valid, state)
		}
	}
	comparisonRecord, err := db.decisionComparisonRecord(ctx, projectID, evaluation.ComparisonFingerprint)
	if err != nil {
		return governance.GovernanceStatus{}, err
	}
	comparison, _, _, err := db.canonicalAnalyticsComparison(ctx, projectID, comparisonRecord)
	if err != nil {
		return governance.GovernanceStatus{}, err
	}
	return governance.DeriveStatus(governance.StatusInput{ProjectID: projectID, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, EvaluationFingerprint: evaluation.Fingerprint, CurrentSnapshotFingerprint: evaluation.CurrentSnapshot, ComparisonFingerprint: evaluation.ComparisonFingerprint, EvaluationAt: evaluation.EvaluatedAt, AsOf: asOf.UTC(), MaximumAge: 366 * 24 * time.Hour, PolicyFailed: evaluation.Summary.Failed > 0, RegressionDetected: len(comparison.Items) > 0, EvidenceFreshnessKnown: true, Recommendations: valid})
}

func decisionRegressionSignals(comparison regression.Comparison) []decisionintelligence.RegressionSignal {
	values := make([]decisionintelligence.RegressionSignal, 0)
	for _, item := range comparison.Items {
		switch item.Change {
		case regression.ChangeNewFinding, regression.ChangeRiskIncreased, regression.ChangeEvidenceStale, regression.ChangeEvidenceContradiction, regression.ChangeCoverageDecreased, regression.ChangeReproducibilityChanged:
			encoded, _ := json.Marshal(struct {
				ComparisonFingerprint string
				Item                  regression.Item
			}{comparison.Fingerprint, item})
			digest := analyticsSourceFingerprint([]string{string(encoded)})
			values = append(values, decisionintelligence.RegressionSignal{Fingerprint: digest, ChangeType: string(item.Change), Impact: string(item.Impact), Confidence: string(item.Confidence)})
		}
	}
	sort.Slice(values, func(left, right int) bool { return values[left].Fingerprint < values[right].Fingerprint })
	return values
}

// SaveDecisionSnapshot writes only canonical bounded decision metadata. It is
// idempotent for the same decision state and never writes any R18–R21 owner.
func (db *DB) SaveDecisionSnapshot(ctx context.Context, snapshot decisionintelligence.DecisionSnapshot) error {
	if db == nil || db.sql == nil || !decisionintelligence.ValidateSnapshot(snapshot) {
		return errors.New("invalid decision snapshot")
	}
	sourcesJSON, err := json.Marshal(snapshot.SourceFingerprints)
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil || len(sourcesJSON) > 64<<10 || len(snapshotJSON) > 256<<10 {
		return errors.New("invalid decision snapshot serialization")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO decision_snapshots(project_id,snapshot_fingerprint,schema_version,decision_version,generated_at,source_fingerprints_json,snapshot_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(project_id,snapshot_fingerprint) DO NOTHING`, snapshot.ProjectID, snapshot.Fingerprint, snapshot.SchemaVersion, snapshot.DecisionVersion, formatStorageTime(snapshot.GeneratedAt), string(sourcesJSON), string(snapshotJSON))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var stored string
		if err := tx.QueryRowContext(ctx, `SELECT snapshot_json FROM decision_snapshots WHERE project_id=? AND snapshot_fingerprint=?`, snapshot.ProjectID, snapshot.Fingerprint).Scan(&stored); err != nil || stored != string(snapshotJSON) {
			return errors.New("conflicting immutable decision snapshot")
		}
		return tx.Commit()
	}
	for _, candidate := range snapshot.Candidates {
		candidateJSON, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO decision_candidates(project_id,snapshot_fingerprint,candidate_fingerprint,priority,state,action,candidate_json) VALUES(?,?,?,?,?,?,?)`, snapshot.ProjectID, snapshot.Fingerprint, candidate.Fingerprint, string(candidate.Priority), string(candidate.State), string(candidate.Action), string(candidateJSON)); err != nil {
			return err
		}
		for index, factor := range candidate.Factors {
			encoded, err := json.Marshal(factor)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO decision_factors(project_id,snapshot_fingerprint,candidate_fingerprint,position,factor_json) VALUES(?,?,?,?,?)`, snapshot.ProjectID, snapshot.Fingerprint, candidate.Fingerprint, index, string(encoded)); err != nil {
				return err
			}
		}
		recommendationJSON, err := json.Marshal(candidate.Recommendation)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO decision_recommendations(project_id,snapshot_fingerprint,candidate_fingerprint,recommendation_json) VALUES(?,?,?,?)`, snapshot.ProjectID, snapshot.Fingerprint, candidate.Fingerprint, string(recommendationJSON)); err != nil {
			return err
		}
		for index, constraint := range candidate.Constraints {
			encoded, err := json.Marshal(constraint)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO decision_constraints(project_id,snapshot_fingerprint,candidate_fingerprint,position,constraint_json) VALUES(?,?,?,?,?)`, snapshot.ProjectID, snapshot.Fingerprint, candidate.Fingerprint, index, string(encoded)); err != nil {
				return err
			}
		}
		lineageJSON, err := json.Marshal(candidate.Lineage)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO decision_lineage(project_id,snapshot_fingerprint,candidate_fingerprint,lineage_json) VALUES(?,?,?,?)`, snapshot.ProjectID, snapshot.Fingerprint, candidate.Fingerprint, string(lineageJSON)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadVerifiedDecisionSnapshot returns a stored snapshot only when fresh
// canonical source reconstruction produces byte-identical decision content.
func (db *DB) LoadVerifiedDecisionSnapshot(ctx context.Context, projectID string, request DecisionRequest) (decisionintelligence.DecisionSnapshot, bool, error) {
	expected, err := db.BuildDecisionSnapshot(ctx, projectID, request)
	if err != nil {
		return decisionintelligence.DecisionSnapshot{}, false, err
	}
	var stored string
	err = db.sql.QueryRowContext(ctx, `SELECT snapshot_json FROM decision_snapshots WHERE project_id=? AND snapshot_fingerprint=? AND schema_version=? AND decision_version=?`, projectID, expected.Fingerprint, decisionintelligence.SchemaVersion, decisionintelligence.DecisionVersion).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return decisionintelligence.DecisionSnapshot{}, false, nil
	}
	if err != nil {
		return decisionintelligence.DecisionSnapshot{}, false, err
	}
	var cached decisionintelligence.DecisionSnapshot
	if err := json.Unmarshal([]byte(stored), &cached); err != nil || !decisionintelligence.ValidateSnapshot(cached) || !equalAnalyticsJSON(cached, expected) {
		return decisionintelligence.DecisionSnapshot{}, false, errors.New("invalid or stale decision snapshot cache")
	}
	return cached, true, nil
}
