package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestContinuousAssessmentPersistenceIsProjectScopedIdempotentAndRestartSafe(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r19.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 10, 0, 0, 0, time.UTC)
	policy := AssessmentPolicyRecord{ProjectID: "alpha", PolicyID: repeatHex("a"), Name: "production-security", Version: 1, Fingerprint: repeatHex("a"), PolicyJSON: `{"project_id":"alpha","version":1}`, CreatedAt: createdAt}
	if err := database.SaveAssessmentPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := database.LoadAssessmentPolicy(ctx, "beta", policy.PolicyID); err == nil {
		t.Fatal("expected cross-project policy read rejection")
	}
	baseline := AssessmentBaselineRecord{ProjectID: "alpha", BaselineID: repeatHex("b"), SnapshotID: repeatHex("c"), PolicyID: policy.PolicyID, CampaignID: "campaign-1", Fingerprint: repeatHex("b"), BaselineJSON: `{"project_id":"alpha"}`, CreatedAt: createdAt}
	if err := database.SaveAssessmentBaseline(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	evaluation := AssessmentEvaluationRecord{ProjectID: "alpha", EvaluationID: repeatHex("d"), PolicyID: policy.PolicyID, BaselineID: baseline.BaselineID, BaselineSnapshotID: baseline.SnapshotID, CurrentSnapshotID: repeatHex("e"), ComparisonID: repeatHex("f"), Status: "failed", Fingerprint: repeatHex("d"), EvaluationJSON: `{"project_id":"alpha","summary":{"failed":1}}`, CreatedAt: createdAt}
	if err := database.SaveAssessmentEvaluation(ctx, evaluation); err != nil {
		t.Fatal(err)
	}
	action := AssessmentActionRecord{ProjectID: "alpha", ActionID: repeatHex("1"), EvaluationID: evaluation.EvaluationID, RuleID: "coverage", Kind: "rerun_bounded_assessment", Priority: "high", Status: "recommended", CampaignID: "campaign-1", Fingerprint: repeatHex("1"), ActionJSON: `{"project_id":"alpha","status":"recommended"}`, CreatedAt: createdAt}
	if err := database.SaveAssessmentAction(ctx, action); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.LoadAssessmentEvaluation(ctx, "alpha", evaluation.EvaluationID)
	if err != nil || loaded.Fingerprint != evaluation.Fingerprint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	actions, err := database.ListAssessmentActions(ctx, "alpha", evaluation.EvaluationID)
	if err != nil || len(actions) != 1 || actions[0].ActionID != action.ActionID {
		t.Fatalf("actions=%+v err=%v", actions, err)
	}
}
