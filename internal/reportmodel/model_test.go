package reportmodel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSnapshotNormalizesOrderAndUsesStableContentFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Findings:      []Finding{{ID: "finding-b", Severity: "high", RiskScore: 70}, {ID: "finding-a", Severity: "medium", RiskScore: 50}},
		Limitations:   []string{"surface membership unavailable", "owner unavailable"},
		Coverage:      CoverageMetric{Definition: "executed tasks divided by planned tasks", Numerator: 0, Denominator: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Findings:      []Finding{{ID: "finding-a", Severity: "medium", RiskScore: 50}, {ID: "finding-b", Severity: "high", RiskScore: 70}},
		Limitations:   []string{"owner unavailable", "surface membership unavailable"},
		Coverage:      CoverageMetric{Definition: "executed tasks divided by planned tasks", Numerator: 0, Denominator: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints differ: %q != %q", first.Fingerprint, second.Fingerprint)
	}
	if got := first.Coverage.Display(); got != "N/A" {
		t.Fatalf("zero denominator coverage = %q, want N/A", got)
	}
	if first.Findings[0].ID != "finding-a" || first.Limitations[0] != "owner unavailable" {
		t.Fatalf("snapshot was not normalized: %+v", first)
	}
}

func TestSnapshotRejectsSecretLikeFindingIdentity(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Findings: []Finding{{ID: "token=opaque", Severity: "high", RiskScore: 70}}, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like finding identity was accepted")
	}
}

func TestSnapshotRejectsSecretLikeContextIdentity(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-token=opaque", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like campaign identity was accepted")
	}
}

func TestSnapshotRejectsSecretLikeTarget(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", Target: "https://app.test/?token=opaque", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like target was accepted")
	}
}

func TestSnapshotNormalizesEmptyCollectionsToJSONArrays(t *testing.T) {
	snapshot, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), `"findings":null`) || strings.Contains(string(encoded), `"limitations":null`) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}

func TestSnapshotNormalizesEvidenceVerificationDetailsAndIncludesThemInFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Coverage:      CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0},
		Evidence: EvidenceVerification{Details: []EvidenceDetail{
			{FindingID: "finding-b", Verification: "supported", Freshness: "current", Reproducibility: "single_observation", Gaps: []string{}, Contradictions: []string{}},
			{FindingID: "finding-a", Verification: "contradictory", Freshness: "stale", Reproducibility: "cannot_reproduce", Gaps: []string{"OBSERVATION_MISSING"}, Contradictions: []string{"PROJECT_MISMATCH"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Coverage:      CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0},
		Evidence: EvidenceVerification{Details: []EvidenceDetail{
			{FindingID: "finding-a", Verification: "contradictory", Freshness: "stale", Reproducibility: "cannot_reproduce", Gaps: []string{"OBSERVATION_MISSING"}, Contradictions: []string{"PROJECT_MISMATCH"}},
			{FindingID: "finding-b", Verification: "supported", Freshness: "current", Reproducibility: "single_observation", Gaps: []string{}, Contradictions: []string{}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Evidence.Details[0].FindingID != "finding-a" {
		t.Fatalf("evidence state was not normalized: first=%+v second=%+v", first, second)
	}
}

func TestSnapshotNormalizesRegressionDetailsAndIncludesThemInFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Regression: RegressionIntelligence{ComparisonFingerprint: "comparison-1", Details: []RegressionDetail{{Category: "evidence", Change: "evidence_stale", Subject: "finding-b", Impact: "high", Confidence: "confirmed", Reason: "evidence_stale"}, {Category: "surface", Change: "new_endpoint", Subject: "endpoint-a", Impact: "informational", Confidence: "confirmed", Reason: "endpoint_added"}}}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Regression: RegressionIntelligence{ComparisonFingerprint: "comparison-1", Details: []RegressionDetail{{Category: "surface", Change: "new_endpoint", Subject: "endpoint-a", Impact: "informational", Confidence: "confirmed", Reason: "endpoint_added"}, {Category: "evidence", Change: "evidence_stale", Subject: "finding-b", Impact: "high", Confidence: "confirmed", Reason: "evidence_stale"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Regression.Details[0].Subject != "finding-b" {
		t.Fatalf("regression state was not normalized: first=%+v second=%+v", first, second)
	}
}

func TestSnapshotNormalizesAssessmentControlAndIncludesItInFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Assessment: AssessmentControl{EvaluationFingerprint: "evaluation-1", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", CurrentSnapshotFingerprint: "snapshot-1", Status: "failed", FailedRules: 1, Decisions: []AssessmentDecision{{RuleID: "coverage", Status: "fail", ObservedValue: 7000, ExpectedValue: 8000, Unit: "basis_points", Explanation: "recorded coverage is below threshold"}, {RuleID: "new-findings", Status: "pass", ObservedValue: 0, ExpectedValue: 0, Unit: "count", Explanation: "no new findings"}}, Actions: []AssessmentAction{{RuleID: "coverage", Kind: "rerun_bounded_assessment", Priority: "high", Rationale: "coverage is incomplete"}}}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Assessment: AssessmentControl{EvaluationFingerprint: "evaluation-1", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", CurrentSnapshotFingerprint: "snapshot-1", Status: "failed", FailedRules: 1, Decisions: []AssessmentDecision{{RuleID: "new-findings", Status: "pass", ObservedValue: 0, ExpectedValue: 0, Unit: "count", Explanation: "no new findings"}, {RuleID: "coverage", Status: "fail", ObservedValue: 7000, ExpectedValue: 8000, Unit: "basis_points", Explanation: "recorded coverage is below threshold"}}, Actions: []AssessmentAction{{RuleID: "coverage", Kind: "rerun_bounded_assessment", Priority: "high", Rationale: "coverage is incomplete"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Assessment.Decisions[0].RuleID != "coverage" || first.Assessment.Actions[0].Kind != "rerun_bounded_assessment" {
		t.Fatalf("assessment control was not normalized: first=%+v second=%+v", first, second)
	}
}

func TestSnapshotNormalizesGovernanceAndIncludesItInFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Governance: GovernanceControl{Overall: "stale", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", EvaluationFingerprint: "evaluation-1", ComparisonFingerprint: "comparison-1", UnresolvedActions: 2, StaleReasons: []string{"evaluation_max_age_exceeded", "policy_changed"}, Limitations: []string{"evidence_freshness_unknown"}, Decisions: []GovernanceDecision{{RecommendationFingerprint: "action-b", State: "acknowledged", PreviousState: "recommended", EventType: "governance.recommendation.acknowledged", Actor: "operator-a", Reason: "reviewed regression", OccurredAt: "2026-08-20T12:00:00Z", EventFingerprint: "event-b"}, {RecommendationFingerprint: "action-a", State: "accepted", PreviousState: "acknowledged", EventType: "governance.recommendation.accepted", Actor: "operator-a", Reason: "accepted triage", OccurredAt: "2026-08-20T12:01:00Z", EventFingerprint: "event-a"}}}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Governance: GovernanceControl{Overall: "stale", PolicyFingerprint: "policy-1", BaselineFingerprint: "baseline-1", EvaluationFingerprint: "evaluation-1", ComparisonFingerprint: "comparison-1", UnresolvedActions: 2, StaleReasons: []string{"policy_changed", "evaluation_max_age_exceeded"}, Limitations: []string{"evidence_freshness_unknown"}, Decisions: []GovernanceDecision{{RecommendationFingerprint: "action-a", State: "accepted", PreviousState: "acknowledged", EventType: "governance.recommendation.accepted", Actor: "operator-a", Reason: "accepted triage", OccurredAt: "2026-08-20T12:01:00Z", EventFingerprint: "event-a"}, {RecommendationFingerprint: "action-b", State: "acknowledged", PreviousState: "recommended", EventType: "governance.recommendation.acknowledged", Actor: "operator-a", Reason: "reviewed regression", OccurredAt: "2026-08-20T12:00:00Z", EventFingerprint: "event-b"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Governance.Decisions[0].RecommendationFingerprint != "action-a" || first.Governance.StaleReasons[0] != "evaluation_max_age_exceeded" {
		t.Fatalf("governance state was not normalized: first=%+v second=%+v", first, second)
	}
}

func TestSnapshotNormalizesDecisionIntelligenceAndIncludesItInFingerprint(t *testing.T) {
	decision := DecisionIntelligenceControl{Status: "blocked", SnapshotFingerprint: "decision-snapshot-1", DataQuality: "contradictory", Confidence: "unknown", PriorityP0: 1, GovernanceBlockers: []string{"governance_unknown"}, Limitations: []string{"decision_source_quality_contradictory"}, Recommendations: []DecisionRecommendation{{ID: "candidate-b", Fingerprint: "candidate-b", Priority: "P1", State: "blocked", Action: "investigate_regression", Confidence: "unknown", Quality: "contradictory", NonExecuting: true, Reasons: []string{"validated_r18_regression_requires_review"}, Factors: []DecisionFactor{{Type: "active_regression", Weight: 45, SourceFingerprint: "comparison-1"}}, Constraints: []DecisionConstraint{{Type: "data_quality_failure", Reason: "validated_r21_data_quality_is_contradictory"}}, Lineage: []string{"comparison-1", "evaluation-1"}}, {ID: "candidate-a", Fingerprint: "candidate-a", Priority: "P0", State: "blocked", Action: "verify_evidence", Confidence: "unknown", Quality: "contradictory", NonExecuting: true, Reasons: []string{"validated_r18_evidence_freshness_requires_verification"}, Factors: []DecisionFactor{{Type: "evidence_stale", Weight: 35, SourceFingerprint: "comparison-2"}}, Constraints: []DecisionConstraint{{Type: "data_quality_failure", Reason: "validated_r21_data_quality_is_contradictory"}}, Lineage: []string{"comparison-2", "evaluation-2"}}}}
	first, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Decision: decision})
	if err != nil {
		t.Fatal(err)
	}
	decision.Recommendations[0], decision.Recommendations[1] = decision.Recommendations[1], decision.Recommendations[0]
	second, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Decision: decision})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Decision.Recommendations[0].ID != "candidate-a" {
		t.Fatalf("decision projection was not normalized: first=%+v second=%+v", first, second)
	}
	decision.PriorityP0 = 0
	changed, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks"}, Decision: decision})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint == first.Fingerprint {
		t.Fatal("report fingerprint omitted a semantic R22 priority change")
	}
}
