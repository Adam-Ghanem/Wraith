package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"report", "--project", "alpha", "--campaign", "campaign-1", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"finding-1"`) || !strings.Contains(output.String(), `"schema_version":"r16.v1"`) {
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
