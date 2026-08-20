package decisionintelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
)

func TestEvaluateCreatesDeterministicImmediateRegressionDecision(t *testing.T) {
	input := decisionInput(t)
	input.RegressionSignals = []RegressionSignal{{
		Fingerprint: testFingerprint("critical-regression"),
		ChangeType:  "risk_increased",
		Impact:      "critical",
		Confidence:  "confirmed",
	}}
	input.Policy.FailedRules = 1

	first, err := Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	second, err := Evaluate(input)
	if err != nil {
		t.Fatalf("second Evaluate() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Evaluate() is not deterministic\nfirst=%+v\nsecond=%+v", first, second)
	}
	if !ValidateSnapshot(first) {
		t.Fatal("ValidateSnapshot() rejected deterministic decision snapshot")
	}
	if len(first.Candidates) == 0 {
		t.Fatal("Evaluate() produced no candidate for a verified critical regression")
	}
	decision := first.Candidates[0]
	if decision.Action != ActionInvestigateRegression || decision.Priority != PriorityP0 || decision.State != CandidateAllowed {
		t.Fatalf("unexpected critical decision = %+v", decision)
	}
	if len(decision.Factors) != 2 || decision.Factors[0].Type != FactorActiveRegression || decision.Factors[1].Type != FactorPolicyFailure {
		t.Fatalf("unexpected deterministic factors = %+v", decision.Factors)
	}
	if decision.Recommendation.Type != ActionInvestigateRegression || !decision.Recommendation.NonExecuting || len(decision.Reasons) == 0 {
		t.Fatalf("decision must carry explicit non-executing recommendation metadata and reasons: %+v", decision)
	}
}

func TestEvaluateBlocksActionWhenDataQualityIsContradictory(t *testing.T) {
	input := decisionInput(t)
	input.Analytics = analyticsSnapshot(t, analytics.DataQualityContradictory)
	input.Lineage.AnalyticsFingerprint = input.Analytics.Fingerprint
	input.RegressionSignals = []RegressionSignal{{
		Fingerprint: testFingerprint("contradictory-regression"),
		ChangeType:  "evidence_contradiction",
		Impact:      "high",
		Confidence:  "confirmed",
	}}

	snapshot, err := Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(snapshot.Candidates) == 0 {
		t.Fatal("Evaluate() produced no decision-quality candidate")
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.State != CandidateBlocked || !containsConstraint(candidate.Constraints, ConstraintDataQualityFailure) {
			t.Fatalf("contradictory input must fail closed, candidate=%+v", candidate)
		}
	}
}

func TestEvaluateCreatesEvidenceVerificationDecisionForFreshnessDegradation(t *testing.T) {
	input := decisionInput(t)
	input.Analytics = analyticsSnapshotWithStaleEvidence(t)
	input.Lineage.AnalyticsFingerprint = input.Analytics.Fingerprint

	snapshot, err := Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(snapshot.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want one evidence decision", len(snapshot.Candidates))
	}
	candidate := snapshot.Candidates[0]
	if candidate.Action != ActionVerifyEvidence || candidate.State != CandidateAllowed || candidate.Factors[0].Type != FactorEvidenceStale {
		t.Fatalf("unexpected freshness-degradation decision = %+v", candidate)
	}
}

func TestEvaluateRejectsCrossProjectSourceLineage(t *testing.T) {
	input := decisionInput(t)
	input.Lineage.ProjectID = "project-b"
	if _, err := Evaluate(input); err == nil || !strings.Contains(err.Error(), "project") {
		t.Fatalf("Evaluate() error = %v, want cross-project rejection", err)
	}
}

func TestValidateSnapshotRejectsForgedDerivedPriority(t *testing.T) {
	input := decisionInput(t)
	input.RegressionSignals = []RegressionSignal{{
		Fingerprint: testFingerprint("regression"),
		ChangeType:  "new_finding",
		Impact:      "high",
		Confidence:  "confirmed",
	}}
	snapshot, err := Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	snapshot.Candidates[0].Priority = PriorityP4
	if ValidateSnapshot(snapshot) {
		t.Fatal("ValidateSnapshot() accepted a forged derived priority with the original fingerprint")
	}
}

func decisionInput(t *testing.T) Input {
	t.Helper()
	analyticsSnapshot := analyticsSnapshot(t, analytics.DataQualityComplete)
	return Input{
		ProjectID:   "project-a",
		GeneratedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Analytics:   analyticsSnapshot,
		Lineage: DecisionLineage{
			ProjectID:             "project-a",
			AnalyticsFingerprint:  analyticsSnapshot.Fingerprint,
			ComparisonFingerprint: testFingerprint("comparison"),
			EvaluationFingerprint: testFingerprint("evaluation"),
			PolicyFingerprint:     testFingerprint("policy"),
			GovernanceFingerprint: testFingerprint("governance"),
		},
		Policy: PolicyState{Fingerprint: testFingerprint("policy"), Status: "pass"},
		Governance: GovernanceState{
			Fingerprint: testFingerprint("governance"),
			Overall:     "healthy",
		},
	}
}

func analyticsSnapshot(t *testing.T, quality analytics.DataQualityStatus) analytics.AnalyticsSnapshot {
	t.Helper()
	from := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	first := analytics.HistoricalRecord{ProjectID: "project-a", Timestamp: from, SourceFingerprint: testFingerprint("first-source"), SnapshotFingerprint: testFingerprint("first-snapshot"), ComparisonFingerprint: testFingerprint("first-comparison"), EvaluationFingerprint: testFingerprint("first-evaluation"), Surface: analytics.SurfaceCounts{CoverageDefinition: "coverage", CoverageDenominator: 1}, Governance: analytics.GovernanceCounts{}}
	second := analytics.HistoricalRecord{ProjectID: "project-a", Timestamp: to, SourceFingerprint: testFingerprint("second-source"), SnapshotFingerprint: testFingerprint("second-snapshot"), ComparisonFingerprint: testFingerprint("second-comparison"), EvaluationFingerprint: testFingerprint("second-evaluation"), Surface: analytics.SurfaceCounts{CoverageDefinition: "coverage", CoverageDenominator: 1}, Governance: analytics.GovernanceCounts{}}
	if quality == analytics.DataQualityContradictory {
		second.Limitations = []string{"source_contradiction"}
	}
	input := analytics.SnapshotInput{ProjectID: "project-a", Window: analytics.Window{From: from, To: to}, AsOf: to, Records: []analytics.HistoricalRecord{first, second}}
	snapshot, err := analytics.BuildSnapshot(input)
	if err != nil {
		t.Fatalf("analytics.BuildSnapshot() error = %v", err)
	}
	if snapshot.DataQuality.Status != quality {
		t.Fatalf("analytics data quality = %q, want %q", snapshot.DataQuality.Status, quality)
	}
	return snapshot
}

func analyticsSnapshotWithStaleEvidence(t *testing.T) analytics.AnalyticsSnapshot {
	t.Helper()
	from := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	first := analytics.HistoricalRecord{ProjectID: "project-a", Timestamp: from, SourceFingerprint: testFingerprint("stale-first-source"), SnapshotFingerprint: testFingerprint("stale-first-snapshot"), ComparisonFingerprint: testFingerprint("stale-first-comparison"), EvaluationFingerprint: testFingerprint("stale-first-evaluation"), Surface: analytics.SurfaceCounts{CoverageDefinition: "coverage", CoverageDenominator: 1}, Governance: analytics.GovernanceCounts{}}
	second := analytics.HistoricalRecord{ProjectID: "project-a", Timestamp: to, SourceFingerprint: testFingerprint("stale-second-source"), SnapshotFingerprint: testFingerprint("stale-second-snapshot"), ComparisonFingerprint: testFingerprint("stale-second-comparison"), EvaluationFingerprint: testFingerprint("stale-second-evaluation"), Evidence: analytics.EvidenceCounts{Stale: 1}, Surface: analytics.SurfaceCounts{CoverageDefinition: "coverage", CoverageDenominator: 1}, Governance: analytics.GovernanceCounts{}}
	snapshot, err := analytics.BuildSnapshot(analytics.SnapshotInput{ProjectID: "project-a", Window: analytics.Window{From: from, To: to}, AsOf: to, Records: []analytics.HistoricalRecord{first, second}})
	if err != nil {
		t.Fatalf("analytics.BuildSnapshot() error = %v", err)
	}
	return snapshot
}

func testFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func containsConstraint(values []DecisionConstraint, expected ConstraintType) bool {
	for _, value := range values {
		if value.Type == expected {
			return true
		}
	}
	return false
}
