package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestReportCommandIsProjectScopedAndReadOnly(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertSecurityFinding(ctx, storage.SecurityFindingRecord{FindingID: "finding-1", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", CorrelationID: "correlation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", Class: "sql", Subtype: "validated_sql", Title: "Validated behavior", Description: "Bounded evidence", RemediationHint: "Use parameterized queries.", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: now, LastSeenAt: now, ValidatedAt: now, RiskCalculatedAt: now, Fingerprint: "finding-fingerprint", EvidenceReferences: []string{"observation-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveEvidenceCorrelationSnapshot(ctx, storage.EvidenceCorrelationSnapshotRecord{ProjectID: "alpha", CampaignID: "campaign-1", FindingID: "finding-1", Fingerprint: "evidence-fingerprint", VerificationState: "supported", FreshnessState: "current", ReproducibilityState: "single_observation", SnapshotJSON: `{"gaps":[],"contradictions":[]}`, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"finding-1"`) || !strings.Contains(output.String(), `"schema_version":"r16.v1"`) || !strings.Contains(output.String(), `"evidence_verification":{"details":[{"finding_id":"finding-1","verification":"supported"`) {
		t.Fatalf("output=%s", output.String())
	}
	if err := Run(ctx, []string{"report", "--project", "beta", "--campaign", "campaign-1", "--format", "json", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("cross-project report was accepted")
	}
}

func TestReportCommandWritesRequestedLocalOutputFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-output.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "report.md")
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "markdown", "--output", outputPath, "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil || !strings.Contains(string(contents), "# Wraith Assessment Report") {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
}

func TestReportCommandAppliesAuthoritativeFindingSeverityFilter(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-filter.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertSecurityFinding(ctx, storage.SecurityFindingRecord{FindingID: "finding-high", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", CorrelationID: "correlation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", Class: "sql", Subtype: "validated_sql", Title: "Validated behavior", Description: "Bounded evidence", RemediationHint: "Use parameterized queries.", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: now, LastSeenAt: now, ValidatedAt: now, RiskCalculatedAt: now, Fingerprint: "finding-fingerprint", EvidenceReferences: []string{"observation-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--severity", "low", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "finding-high") {
		t.Fatalf("filter ignored: %s", output.String())
	}
}

func TestReportCommandUsesRecordedCampaignTaskCoverage(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-coverage.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "failed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateCampaignCycle(ctx, storage.CampaignCycleRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", ScopeVersion: "scope-v1", AssessmentID: "assessment-1", SurfaceSnapshotID: "surface-1", Status: "failed", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", TaskID: "task-1", AssessmentTaskID: "crawl", Status: "completed", Priority: 2}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", TaskID: "task-2", AssessmentTaskID: "discovery", Status: "blocked", Priority: 1}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"numerator":1,"denominator":2`) {
		t.Fatalf("coverage=%s", output.String())
	}
}

func TestReportCommandAppliesExactFindingSelection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-finding.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"finding-1", "finding-2"} {
		if err := database.UpsertSecurityFinding(ctx, storage.SecurityFindingRecord{FindingID: id, ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-" + id, CorrelationID: "correlation-" + id, EndpointID: "endpoint-1", ParameterID: "parameter-1", Class: "sql", Subtype: "validated_sql", Title: "Validated behavior", Description: "Bounded evidence", RemediationHint: "Use parameterized queries.", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: now, LastSeenAt: now, ValidatedAt: now, RiskCalculatedAt: now, Fingerprint: "fingerprint-" + id, EvidenceReferences: []string{"observation-" + id}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--finding", "finding-2", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "finding-2") || strings.Contains(output.String(), "finding-1") {
		t.Fatalf("output=%s", output.String())
	}
}

func TestReportCommandSupportsMutuallyExclusiveExecutiveAndTechnicalModes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-mode.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--executive", "--format", "markdown", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), "## Executive Summary") {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--executive", "--technical", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("combined report modes were accepted")
	}
}

func TestReportCommandIncludesAuthoritativeCampaignMetadata(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-campaign-metadata.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"campaign_status":"completed"`, `"profile":"safe"`, `"target":"https://app.test"`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %s in %s", expected, output.String())
		}
	}
}

func TestReportCommandIncludesLatestPersistedRegressionForSelectedCampaign(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-regression.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 4, 0, 0, 0, time.UTC)
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	baseline, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-old", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, EndpointIDs: []string{"endpoint-old"}, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Hour), EndpointIDs: []string{"endpoint-old", "endpoint-new"}, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []regression.Snapshot{baseline, current} {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.SaveRegressionSnapshot(ctx, storage.RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: snapshot.Fingerprint, CampaignID: snapshot.CampaignID, ScopeVersion: "scope-v1", SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
			t.Fatal(err)
		}
	}
	comparison, err := regression.Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	comparisonJSON, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveRegressionComparison(ctx, storage.RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baseline.Fingerprint, CurrentSnapshotID: current.Fingerprint, Fingerprint: comparison.Fingerprint, ComparisonJSON: string(comparisonJSON), CreatedAt: current.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"security_regression"`) || !strings.Contains(output.String(), "endpoint-new") {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}

func TestReportCommandIncludesLatestPersistedAssessmentEvaluationForSelectedCampaign(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "report-assessment.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 6, 0, 0, 0, time.UTC)
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	baselineSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-old", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	currentSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Hour), EndpointIDs: []string{"endpoint-new"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
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
	if err := database.SaveRegressionComparison(ctx, storage.RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, Fingerprint: comparison.Fingerprint, ComparisonJSON: string(comparisonJSON), CreatedAt: currentSnapshot.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	policy, err := continuousassessment.NewPolicy(continuousassessment.PolicyInput{ProjectID: "alpha", Name: "production-security", Version: 1, Rules: []continuousassessment.PolicyRule{{ID: "no-regressions", Type: continuousassessment.RuleRegression, Operator: continuousassessment.OperatorMaximum, Threshold: continuousassessment.Threshold{Value: 0, Unit: continuousassessment.UnitCount}, Effect: continuousassessment.EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentPolicy(ctx, storage.AssessmentPolicyRecord{ProjectID: "alpha", PolicyID: policy.Fingerprint, Name: policy.Name, Version: policy.Version, Fingerprint: policy.Fingerprint, PolicyJSON: `{"project_id":"alpha","name":"production-security","version":1,"rules":[{"id":"no-regressions","type":"regression","operator":"maximum","threshold":{"value":0,"unit":"count"},"effect":"fail"}]}`, CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	baseline, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CampaignID: baselineSnapshot.CampaignID, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentBaseline(ctx, storage.AssessmentBaselineRecord{ProjectID: "alpha", BaselineID: baseline.Fingerprint, SnapshotID: baseline.SnapshotFingerprint, PolicyID: baseline.PolicyFingerprint, CampaignID: baseline.CampaignID, Fingerprint: baseline.Fingerprint, BaselineJSON: string(baselineJSON), CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	evaluation, err := continuousassessment.Evaluate(continuousassessment.EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: currentSnapshot.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	evaluationJSON, err := json.Marshal(evaluation)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentEvaluation(ctx, storage.AssessmentEvaluationRecord{ProjectID: "alpha", EvaluationID: evaluation.Fingerprint, PolicyID: policy.Fingerprint, BaselineID: baseline.Fingerprint, BaselineSnapshotID: baselineSnapshot.Fingerprint, CurrentSnapshotID: currentSnapshot.Fingerprint, ComparisonID: comparison.Fingerprint, Status: "failed", Fingerprint: evaluation.Fingerprint, EvaluationJSON: string(evaluationJSON), CreatedAt: currentSnapshot.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	if len(evaluation.Actions) != 1 {
		t.Fatalf("actions=%+v", evaluation.Actions)
	}
	action := evaluation.Actions[0]
	actionJSON, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAssessmentAction(ctx, storage.AssessmentActionRecord{ProjectID: "alpha", ActionID: action.ID, EvaluationID: evaluation.Fingerprint, RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Status: string(action.Status), CampaignID: action.CampaignID, Fingerprint: action.ID, ActionJSON: string(actionJSON), CreatedAt: currentSnapshot.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	initial, err := governance.NewRecommendationState(governance.StateInput{ProjectID: "alpha", RecommendationID: action.ID, EvaluationFingerprint: evaluation.Fingerprint, PolicyFingerprint: policy.Fingerprint, BaselineFingerprint: baseline.Fingerprint, RecommendationFingerprint: action.ID, UpdatedAt: currentSnapshot.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	transition, err := governance.Transition(governance.TransitionInput{State: initial, ExpectedState: governance.RecommendationRecommended, NextState: governance.RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed documented regression", At: currentSnapshot.CreatedAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyGovernanceTransition(ctx, initial, transition); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"continuous_assessment":{"evaluation_fingerprint"`) || !strings.Contains(output.String(), `"status":"failed"`) || !strings.Contains(output.String(), `"continuous_assessment_governance":{"overall":"failed"`) || !strings.Contains(output.String(), `"state":"acknowledged"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}
