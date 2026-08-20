package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestGovernAcknowledgesExistingRecommendationOfflineAndFailsConflictsClosed(t *testing.T) {
	ctx := context.Background()
	path, actionID := governCLIFixture(t, ctx)
	if err := Run(ctx, []string{"govern", "acknowledge", "--project", "alpha", "--recommendation", actionID, "--expected-state", "recommended", "--reason", "reviewed documented regression", "--actor", "operator-a", "--as-of", "2026-08-20T12:00:00Z", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var history bytes.Buffer
	if err := Run(ctx, []string{"govern", "history", "--project", "alpha", "--format", "json", "--db", path}, &history, &bytes.Buffer{}); err != nil || !strings.Contains(history.String(), actionID) || !strings.Contains(history.String(), `"event_type":"governance.recommendation.acknowledged"`) {
		t.Fatalf("history=%s err=%v", history.String(), err)
	}
	var listed bytes.Buffer
	if err := Run(ctx, []string{"govern", "recommendations", "--project", "alpha", "--state", "acknowledged", "--format", "json", "--db", path}, &listed, &bytes.Buffer{}); err != nil || !strings.Contains(listed.String(), `"state":"acknowledged"`) {
		t.Fatalf("output=%s err=%v", listed.String(), err)
	}
	if err := Run(ctx, []string{"govern", "accept", "--project", "alpha", "--recommendation", actionID, "--expected-state", "recommended", "--reason", "concurrent overwrite", "--as-of", "2026-08-20T12:01:00Z", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrGovernanceInvalidInput) {
		t.Fatalf("expected optimistic conflict rejection, got %v", err)
	}
	err := Run(ctx, []string{"govern", "check", "--project", "alpha", "--strict", "--as-of", "2026-08-20T12:01:00Z", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrGovernanceFailed) {
		t.Fatalf("expected governance CI failure, got %v", err)
	}
}

func TestGovernStatusReportsUnknownWithoutEvaluationAndStrictFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r20-empty.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"govern", "status", "--project", "alpha", "--format", "json", "--as-of", "2026-08-20T12:00:00Z", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"overall":"unknown"`) || !strings.Contains(output.String(), `"assessment_evaluation_unavailable"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	if err := Run(ctx, []string{"govern", "check", "--project", "alpha", "--strict", "--as-of", "2026-08-20T12:00:00Z", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrGovernanceFailed) {
		t.Fatalf("expected strict unknown governance failure, got %v", err)
	}
}

func TestGovernanceExitCodeClassifiesCIFailuresDeterministically(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(ErrGovernanceFailed) != 1 || ExitCode(ErrGovernanceInvalidInput) != 2 || ExitCode(ErrGovernanceInternal) != 3 {
		t.Fatalf("unexpected governance exit-code mapping")
	}
}

func TestGovernStatusRejectsTamperedPersistedComparison(t *testing.T) {
	ctx := context.Background()
	path, _ := governCLIFixture(t, ctx)
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	evaluations, err := database.ListAssessmentEvaluations(ctx, "alpha")
	if err != nil || len(evaluations) != 1 {
		t.Fatalf("evaluations=%+v err=%v", evaluations, err)
	}
	comparisonID := evaluations[0].ComparisonID
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var encoded string
	if err := raw.QueryRowContext(ctx, `SELECT comparison_json FROM regression_comparisons WHERE project_id=? AND fingerprint=?`, "alpha", comparisonID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var comparison regression.Comparison
	if err := json.Unmarshal([]byte(encoded), &comparison); err != nil {
		t.Fatal(err)
	}
	comparison.Items = nil
	forged, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `UPDATE regression_comparisons SET comparison_json=? WHERE project_id=? AND fingerprint=?`, string(forged), "alpha", comparisonID); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"govern", "status", "--project", "alpha", "--as-of", "2026-08-20T12:00:00Z", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrGovernanceInternal) {
		t.Fatalf("expected tampered comparison rejection, got %v", err)
	}
}

func governCLIFixture(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r20-cli.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 11, 0, 0, 0, time.UTC)
	baselineSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-baseline", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(-time.Hour), Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	currentSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-current", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, EndpointIDs: []string{"endpoint-1"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []regression.Snapshot{baselineSnapshot, currentSnapshot} {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.SaveRegressionSnapshot(ctx, storage.RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: snapshot.Fingerprint, CampaignID: snapshot.CampaignID, ScopeVersion: snapshot.ScopeVersion, SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
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
	if err := database.SaveRegressionComparison(ctx, storage.RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, Fingerprint: comparison.Fingerprint, ComparisonJSON: string(comparisonJSON), CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	policy, err := continuousassessment.ParsePolicy([]byte(`{"project_id":"alpha","name":"governance-policy","version":1,"rules":[{"id":"regression","type":"regression","operator":"maximum","threshold":{"value":0,"unit":"count"},"effect":"fail"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	policyJSON, err := marshalAssessmentPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentPolicy(ctx, storage.AssessmentPolicyRecord{ProjectID: "alpha", PolicyID: policy.Fingerprint, Name: policy.Name, Version: policy.Version, Fingerprint: policy.Fingerprint, PolicyJSON: string(policyJSON), CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	baseline, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: baselineSnapshot.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentBaseline(ctx, storage.AssessmentBaselineRecord{ProjectID: "alpha", BaselineID: baseline.Fingerprint, SnapshotID: baselineSnapshot.Fingerprint, PolicyID: policy.Fingerprint, Fingerprint: baseline.Fingerprint, BaselineJSON: string(baselineJSON), CreatedAt: baseline.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	evaluationValue, err := continuousassessment.Evaluate(continuousassessment.EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	evaluationJSON, err := json.Marshal(evaluationValue)
	if err != nil {
		t.Fatal(err)
	}
	evaluation := storage.AssessmentEvaluationRecord{ProjectID: "alpha", EvaluationID: evaluationValue.Fingerprint, PolicyID: policy.Fingerprint, BaselineID: baseline.Fingerprint, BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, ComparisonID: comparison.Fingerprint, Status: "failed", Fingerprint: evaluationValue.Fingerprint, EvaluationJSON: string(evaluationJSON), CreatedAt: createdAt}
	if err := database.SaveAssessmentEvaluation(ctx, evaluation); err != nil {
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
	if err := database.SaveAssessmentAction(ctx, storage.AssessmentActionRecord{ProjectID: "alpha", ActionID: action.ID, EvaluationID: evaluationValue.Fingerprint, RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Status: string(action.Status), CampaignID: action.CampaignID, Fingerprint: action.ID, ActionJSON: string(actionJSON), CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	return path, action.ID
}
