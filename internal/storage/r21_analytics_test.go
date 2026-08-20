package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

func TestBuildAnalyticsSnapshotAggregatesVerifiedR18R19R20HistoryProjectScoped(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()
	snapshot, err := database.BuildAnalyticsSnapshot(ctx, "alpha", request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Summary.RecordCount != 1 || snapshot.Summary.PolicyFailureCount != 1 || snapshot.Summary.Governance.Acknowledged != 1 || snapshot.Summary.UnresolvedGovernanceCount != 1 || len(snapshot.SourceFingerprints) != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	isolated, err := database.BuildAnalyticsSnapshot(ctx, "beta", request)
	if err != nil {
		t.Fatal(err)
	}
	if isolated.Summary.RecordCount != 0 || len(isolated.SourceFingerprints) != 0 || isolated.DataQuality.ValidRecordCount != 0 {
		t.Fatalf("cross-project data leaked: %+v", isolated)
	}
}

func TestAnalyticsSnapshotCacheIsImmutableAndRefusesForgedOrStaleSource(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()
	snapshot, err := database.BuildAnalyticsSnapshot(ctx, "alpha", request)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAnalyticsSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAnalyticsSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("exact immutable analytics replay should be idempotent: %v", err)
	}
	loaded, found, err := database.LoadVerifiedAnalyticsSnapshot(ctx, "alpha", request)
	if err != nil || !found || loaded.Fingerprint != snapshot.Fingerprint {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	if _, err := database.sql.ExecContext(ctx, `UPDATE analytics_snapshots SET snapshot_json='{}' WHERE project_id=? AND snapshot_fingerprint=?`, "alpha", snapshot.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.LoadVerifiedAnalyticsSnapshot(ctx, "alpha", request); err == nil {
		t.Fatal("expected forged cached analytics payload rejection")
	}
}

func TestBuildAnalyticsSnapshotExcludesMalformedSourceAndRejectsStaleCache(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()
	snapshot, err := database.BuildAnalyticsSnapshot(ctx, "alpha", request)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAnalyticsSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := database.sql.ExecContext(ctx, `UPDATE assessment_evaluations SET evaluation_json='{}' WHERE project_id=?`, "alpha"); err != nil {
		t.Fatal(err)
	}
	degraded, err := database.BuildAnalyticsSnapshot(ctx, "alpha", request)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.DataQuality.ValidRecordCount != 0 || degraded.DataQuality.ExcludedRecordCount != 1 || !containsAnalyticsReason(degraded.DataQuality.ExclusionReasons, "invalid_r19_evaluation") {
		t.Fatalf("degraded source accounting=%+v", degraded.DataQuality)
	}
	if _, found, err := database.LoadVerifiedAnalyticsSnapshot(ctx, "alpha", request); err != nil || found {
		t.Fatalf("stale cache must not be served: found=%t err=%v", found, err)
	}
}

func analyticsStorageFixture(t *testing.T, ctx context.Context) (*DB, AnalyticsRequest) {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "r21.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	baselineSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-a", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: at.Add(-time.Hour), Coverage: regression.Coverage{Definition: "known_surface", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	currentSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-a", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: at, Findings: []regression.Finding{{ID: "finding-a", Fingerprint: repeatAnalyticsHex("a"), Severity: "high", RiskBand: "high", Status: "open"}}, Evidence: []regression.Evidence{{FindingID: "finding-a", Verification: "verified", Freshness: "stale", Reproducibility: "reproducible"}}, Coverage: regression.Coverage{Definition: "known_surface", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []regression.Snapshot{baselineSnapshot, currentSnapshot} {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.SaveRegressionSnapshot(ctx, RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: snapshot.Fingerprint, CampaignID: snapshot.CampaignID, ScopeVersion: snapshot.ScopeVersion, SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
			t.Fatal(err)
		}
	}
	comparison, err := regression.Compare(baselineSnapshot, currentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	comparisonJSON, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveRegressionComparison(ctx, RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, Fingerprint: comparison.Fingerprint, ComparisonJSON: string(comparisonJSON), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	policy, err := continuousassessment.ParsePolicy([]byte(`{"project_id":"alpha","name":"analytics-policy","version":1,"rules":[{"id":"regression","type":"regression","operator":"maximum","threshold":{"value":0,"unit":"count"},"effect":"fail"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentPolicy(ctx, AssessmentPolicyRecord{ProjectID: "alpha", PolicyID: policy.Fingerprint, Name: policy.Name, Version: policy.Version, Fingerprint: policy.Fingerprint, PolicyJSON: string(policyJSON), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	baseline, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CampaignID: "campaign-a", CreatedAt: baselineSnapshot.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentBaseline(ctx, AssessmentBaselineRecord{ProjectID: "alpha", BaselineID: baseline.Fingerprint, SnapshotID: baselineSnapshot.Fingerprint, PolicyID: policy.Fingerprint, CampaignID: "campaign-a", Fingerprint: baseline.Fingerprint, BaselineJSON: string(baselineJSON), CreatedAt: baseline.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	evaluationValue, err := continuousassessment.Evaluate(continuousassessment.EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	evaluationJSON, err := json.Marshal(evaluationValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentEvaluation(ctx, AssessmentEvaluationRecord{ProjectID: "alpha", EvaluationID: evaluationValue.Fingerprint, PolicyID: policy.Fingerprint, BaselineID: baseline.Fingerprint, BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, ComparisonID: comparison.Fingerprint, Status: "failed", Fingerprint: evaluationValue.Fingerprint, EvaluationJSON: string(evaluationJSON), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if len(evaluationValue.Actions) != 1 {
		t.Fatalf("actions=%+v", evaluationValue.Actions)
	}
	action := evaluationValue.Actions[0]
	actionJSON, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentAction(ctx, AssessmentActionRecord{ProjectID: "alpha", ActionID: action.ID, EvaluationID: evaluationValue.Fingerprint, RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Status: string(action.Status), CampaignID: action.CampaignID, Fingerprint: action.ID, ActionJSON: string(actionJSON), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	initial, err := governance.NewRecommendationState(governance.StateInput{ProjectID: "alpha", RecommendationID: action.ID, EvaluationFingerprint: evaluationValue.Fingerprint, PolicyFingerprint: policy.Fingerprint, BaselineFingerprint: baseline.Fingerprint, RecommendationFingerprint: action.ID, UpdatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	acknowledged, err := governance.Transition(governance.TransitionInput{State: initial, ExpectedState: governance.RecommendationRecommended, NextState: governance.RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed historical recommendation", At: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyGovernanceTransition(ctx, initial, acknowledged); err != nil {
		t.Fatal(err)
	}
	return database, AnalyticsRequest{Window: analytics.Window{From: at.Add(-time.Hour), To: at.Add(time.Hour)}, AsOf: at.Add(time.Hour)}
}

func repeatAnalyticsHex(marker string) string {
	for len(marker) < 64 {
		marker += marker
	}
	return marker[:64]
}

func containsAnalyticsReason(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
