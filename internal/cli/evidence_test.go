package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestEvidenceVerifyUsesExactProjectLocalRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence-verify.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	expires := time.Now().UTC().Add(time.Hour)
	if err := database.SaveProjectScope(ctx, policy.ProjectScope{VersionID: "scope-v1", ProjectID: "alpha", Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()}, Rules: []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: "https://app.test", CreatedAt: time.Now().UTC()}}}); err != nil {
		t.Fatal(err)
	}
	validation, err := evidence.NewValidationObservation("alpha", evidence.Endpoint{ProjectID: "alpha", Identity: "endpoint-1"}, evidence.ValidationObservationInput{Source: "validation.r8.test", ObservedAt: now.Add(-2 * time.Hour), ValidatorID: "validator-1", RuleID: "rule-1", Lifecycle: "observed", ReproducibilityKey: "repro-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AppendObservation(ctx, validation.Record()); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertSecurityFinding(ctx, storage.SecurityFindingRecord{FindingID: "finding-1", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", CorrelationID: "correlation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", AssetID: "asset-1", Class: "sql", Subtype: "validated_sql", Title: "Validated behavior", Description: "Bounded evidence", RemediationHint: "Review", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: now, LastSeenAt: now, ValidatedAt: now.Add(-time.Hour), RiskCalculatedAt: now, Fingerprint: "finding-fingerprint", EvidenceReferences: []string{validation.Record().ID}}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateCampaignCycle(ctx, storage.CampaignCycleRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", ScopeVersion: "scope-v1", AssessmentID: "assessment-1", SurfaceSnapshotID: "surface-1", Status: "completed", CreatedAt: now.Add(-3 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", TaskID: "task-1", AssessmentTaskID: "validation", Status: "completed", ResultReference: "validation-1", Priority: 1, FinishedAt: now.Add(-3 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"evidence", "verify", "--project", "alpha", "--finding", "finding-1", "--campaign", "campaign-1", "--authorized", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"verification":"supported"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	if err := Run(ctx, []string{"evidence", "verify", "--project", "beta", "--finding", "finding-1", "--campaign", "campaign-1", "--authorized", "--format", "json", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("cross-project evidence verification was accepted")
	}
	if err := Run(ctx, []string{"evidence", "verify", "--project", "alpha", "--finding", "finding-1", "--campaign", "campaign-1", "--format", "json", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("evidence verification without explicit authorization acknowledgement was accepted")
	}
	if err := Run(ctx, []string{"evidence", "correlate", "--project", "alpha", "--finding", "finding-1", "--campaign", "campaign-1", "--authorized", "--persist", "--format", "json", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	verified, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	snapshots, err := verified.ListEvidenceCorrelationSnapshots(ctx, "alpha", "campaign-1")
	if err != nil || len(snapshots) != 1 || snapshots[0].FindingID != "finding-1" {
		t.Fatalf("snapshots=%+v err=%v", snapshots, err)
	}
}
