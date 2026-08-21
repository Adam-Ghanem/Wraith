package storage

import (
	"context"
	"testing"
	"time"
)

func TestRiskFindingPersistenceIsProjectScopedAndAppendOnly(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	finding := SecurityFindingRecord{FindingID: "finding-1", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", CorrelationID: "correlation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", AssetID: "asset-1", Class: "sql", Subtype: "validated_sql", Title: "Validated injection behavior requires remediation review", Description: "Bounded validation evidence", RemediationHint: "Use parameterized queries.", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: time.Unix(1, 0), LastSeenAt: time.Unix(1, 0), ValidatedAt: time.Unix(1, 0), RiskCalculatedAt: time.Unix(1, 0), Fingerprint: "fingerprint-1", EvidenceReferences: []string{"observation-1"}}
	if err := database.UpsertSecurityFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendFindingHistory(ctx, FindingHistoryRecord{FindingID: finding.FindingID, ProjectID: finding.ProjectID, Event: "created", At: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	findings, err := database.ListSecurityFindings(ctx, "alpha", SecurityFindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].FindingID != finding.FindingID || findings[0].RiskScore != 70 || !findings[0].RiskCalculatedAt.Equal(time.Unix(1, 0).UTC()) {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	other, err := database.ListSecurityFindings(ctx, "beta", SecurityFindingFilter{})
	if err != nil || len(other) != 0 {
		t.Fatalf("other=%#v err=%v", other, err)
	}
	if err := database.UpsertFindingSuppression(ctx, FindingSuppressionRecord{ProjectID: "beta", Fingerprint: finding.Fingerprint, Reason: "cross project", CreatedAt: time.Unix(1, 0)}); err == nil {
		t.Fatal("expected cross-project suppression rejection")
	}
	if err := database.UpsertFindingSuppression(ctx, FindingSuppressionRecord{ProjectID: "alpha", Fingerprint: finding.Fingerprint, Reason: "accepted risk", CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	leaky := finding
	leaky.FindingID, leaky.Fingerprint, leaky.EvidenceReferences = "finding-2", "fingerprint-2", []string{"token=secret"}
	if err := database.UpsertSecurityFinding(ctx, leaky); err == nil {
		t.Fatal("expected secret-like evidence reference rejection")
	}
	leaky = finding
	leaky.FindingID, leaky.Fingerprint, leaky.Description = "finding-3", "fingerprint-3", "authorization: Bearer do-not-persist"
	if err := database.UpsertSecurityFinding(ctx, leaky); err == nil {
		t.Fatal("expected secret-like finding description rejection")
	}
}
