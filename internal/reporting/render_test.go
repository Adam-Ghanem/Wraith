package reporting

import (
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/reportmodel"
)

func TestRenderProducesMachineJSONAndEscapedOfflineHTML(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Limitations: []string{"<untrusted>"}, Coverage: reportmodel.CoverageMetric{Definition: "tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	jsonReport, err := Render("json", snapshot)
	if err != nil || !strings.Contains(string(jsonReport), `"schema_version":"r16.v1"`) {
		t.Fatalf("json=%q err=%v", jsonReport, err)
	}
	htmlReport, err := Render("html", snapshot)
	if err != nil || strings.Contains(string(htmlReport), "<untrusted>") || !strings.Contains(string(htmlReport), "&lt;untrusted&gt;") || strings.Contains(string(htmlReport), "https://") {
		t.Fatalf("html=%q err=%v", htmlReport, err)
	}
}

func TestRenderIncludesExecutiveSummaryWithoutInferringCoverage(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(markdown), "## Executive Summary") || !strings.Contains(string(markdown), "1 recorded completed tasks out of 2") {
		t.Fatalf("markdown=%q err=%v", markdown, err)
	}
	html, err := Render("html", snapshot)
	if err != nil || !strings.Contains(string(html), "Executive Summary") {
		t.Fatalf("html=%q err=%v", html, err)
	}
}

func TestRenderExecutiveOmitsTechnicalFindingList(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Executive Summary") || strings.Contains(string(executive), "finding-1") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "finding-1") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}

func TestRenderSeparatesExecutiveEvidenceAggregationFromTechnicalDetails(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks", Numerator: 1, Denominator: 2}, Evidence: reportmodel.EvidenceVerification{Details: []reportmodel.EvidenceDetail{{FindingID: "finding-1", Verification: "contradictory", Freshness: "stale", Reproducibility: "cannot_reproduce", Gaps: []string{"OBSERVATION_MISSING"}, Contradictions: []string{"PROJECT_MISMATCH"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Evidence & Verification") || !strings.Contains(string(executive), "1 persisted correlation snapshot") || strings.Contains(string(executive), "finding-1") || strings.Contains(string(executive), "PROJECT_MISMATCH") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "## Evidence & Verification") || !strings.Contains(string(technical), "finding-1") || !strings.Contains(string(technical), "PROJECT_MISMATCH") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}

func TestRenderSeparatesExecutiveRegressionAggregationFromTechnicalDetails(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks"}, Regression: reportmodel.RegressionIntelligence{ComparisonFingerprint: "comparison-1", BaselineFingerprint: "baseline-1", CurrentFingerprint: "current-1", BaselineCreatedAt: "2026-08-20T04:00:00Z", CurrentCreatedAt: "2026-08-20T05:00:00Z", ComparedAt: "2026-08-20T05:00:00Z", Details: []reportmodel.RegressionDetail{{Category: "evidence", Change: "evidence_stale", Subject: "finding-1", Impact: "high", Confidence: "confirmed", Reason: "evidence_stale"}}}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Security Regression / Continuous Assessment") || !strings.Contains(string(executive), "Evidence became stale: 1") || strings.Contains(string(executive), "finding-1") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "## Security Regression / Continuous Assessment") || !strings.Contains(string(technical), "finding-1") || !strings.Contains(string(technical), "evidence_stale") || !strings.Contains(string(technical), "Baseline fingerprint: `baseline-1`") || !strings.Contains(string(technical), "Current recorded at: `2026-08-20T05:00:00Z`") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}

func TestRenderSeparatesExecutiveAssessmentAggregationFromTechnicalDetails(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks"}, Assessment: reportmodel.AssessmentControl{EvaluationFingerprint: "evaluation-1", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", CurrentSnapshotFingerprint: "current-1", Status: "failed", FailedRules: 1, Decisions: []reportmodel.AssessmentDecision{{RuleID: "coverage", Status: "fail", ObservedValue: 7000, ExpectedValue: 8000, Unit: "basis_points", Explanation: "recorded coverage is below threshold"}}, Actions: []reportmodel.AssessmentAction{{RuleID: "coverage", Kind: "rerun_bounded_assessment", Priority: "high", Rationale: "coverage is incomplete"}}}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Continuous Assessment Control") || !strings.Contains(string(executive), "Policy status: failed") || strings.Contains(string(executive), "coverage is incomplete") || strings.Contains(string(executive), "evaluation-1") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "## Continuous Assessment Control") || !strings.Contains(string(technical), "evaluation-1") || !strings.Contains(string(technical), "coverage is incomplete") || !strings.Contains(string(technical), "recorded coverage is below threshold") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}

func TestRenderSeparatesExecutiveGovernanceAggregationFromTechnicalAuditLineage(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks"}, Governance: reportmodel.GovernanceControl{Overall: "stale", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", EvaluationFingerprint: "evaluation-1", ComparisonFingerprint: "comparison-1", UnresolvedActions: 1, StaleReasons: []string{"evaluation_max_age_exceeded"}, Limitations: []string{"evidence_freshness_unknown"}, Decisions: []reportmodel.GovernanceDecision{{RecommendationFingerprint: "action-1", State: "acknowledged", PreviousState: "recommended", EventType: "governance.recommendation.acknowledged", Actor: "operator-a", Reason: "reviewed documented regression", OccurredAt: "2026-08-20T12:00:00Z", EventFingerprint: "event-1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Continuous Assessment Governance") || !strings.Contains(string(executive), "Governance status: stale") || strings.Contains(string(executive), "reviewed documented regression") || strings.Contains(string(executive), "action-1") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "## Continuous Assessment Governance") || !strings.Contains(string(technical), "action-1") || !strings.Contains(string(technical), "reviewed documented regression") || !strings.Contains(string(technical), "event-1") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}
