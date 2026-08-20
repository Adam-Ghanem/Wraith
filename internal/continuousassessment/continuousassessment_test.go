package continuousassessment

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

func TestEvaluateProducesDeterministicFailuresAndRecommendations(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	baselineSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-baseline", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Findings: []regression.Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "low", RiskBand: "low", Status: "open"}}, Evidence: []regression.Evidence{{FindingID: "finding-1", Verification: "supported", Freshness: "current", Reproducibility: "repeated_consistent"}}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 10, Denominator: 10}})
	if err != nil {
		t.Fatal(err)
	}
	currentSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-current", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Hour), EndpointIDs: []string{"endpoint-1"}, Findings: []regression.Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "high", RiskBand: "high", Status: "open"}, {ID: "finding-2", Fingerprint: "finding-fingerprint-2", Severity: "high", RiskBand: "high", Status: "open"}}, Evidence: []regression.Evidence{{FindingID: "finding-1", Verification: "supported", Freshness: "stale", Reproducibility: "single_observation", Contradictions: []string{"PROJECT_MISMATCH"}}}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 8, Denominator: 10}})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(baselineSnapshot, currentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "production-security", Version: 1, Rules: []PolicyRule{{ID: "no-new-findings", Type: RuleNewFinding, Operator: OperatorMaximum, Threshold: Threshold{Value: 0, Unit: UnitCount}, Effect: EffectFail}, {ID: "minimum-coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 9000, Unit: UnitBasisPoints}, Effect: EffectFail}, {ID: "no-stale-evidence", Type: RuleEvidenceFreshness, Operator: OperatorMaximum, Threshold: Threshold{Value: 0, Unit: UnitCount}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CampaignID: baselineSnapshot.CampaignID, CreatedAt: currentSnapshot.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	input := EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: currentSnapshot.CreatedAt}
	first, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint || first.Summary.Failed != 3 || len(first.Actions) != 3 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	for _, action := range first.Actions {
		if action.ProjectID != "alpha" || action.ID == "" || action.Status != ActionRecommended {
			t.Fatalf("unsafe or non-deterministic action: %+v", action)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil || !strings.Contains(string(encoded), `"failed":3`) {
		t.Fatalf("evaluation JSON=%s err=%v", encoded, err)
	}
}

func TestEvaluateRejectsCrossProjectBaselineAndForgedSnapshotReference(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	snapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: 1, Rules: []PolicyRule{{ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 0, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "beta", SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: createdAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: snapshot, CurrentSnapshot: snapshot, Comparison: comparison, EvaluatedAt: createdAt}); err == nil {
		t.Fatal("expected cross-project baseline rejection")
	}
}

func TestEvaluateRejectsForgedPolicyFingerprint(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	snapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: 1, Rules: []PolicyRule{{ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 0, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: createdAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	forged := policy
	forged.Rules[0].Threshold.Value = 10000
	if _, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: forged, Baseline: baseline, BaselineSnapshot: snapshot, CurrentSnapshot: snapshot, Comparison: comparison, EvaluatedAt: createdAt}); err == nil {
		t.Fatal("expected forged policy fingerprint rejection")
	}
}

func TestEvaluateRejectsForgedBaselineFingerprint(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	snapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: 1, Rules: []PolicyRule{{ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 0, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: createdAt, PolicyFingerprint: policy.Fingerprint, Description: "approved", CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	forged := baseline
	forged.Description = "changed"
	if _, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: forged, BaselineSnapshot: snapshot, CurrentSnapshot: snapshot, Comparison: comparison, EvaluatedAt: createdAt}); err == nil {
		t.Fatal("expected forged baseline fingerprint rejection")
	}
}

func TestEvaluateUsesBasisPointsForEvidenceVerificationRate(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	snapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Evidence: []regression.Evidence{{FindingID: "finding-1", Verification: "supported", Freshness: "current", Reproducibility: "repeated_consistent"}}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: 1, Rules: []PolicyRule{{ID: "verified-evidence", Type: RuleEvidenceVerification, Operator: OperatorMinimum, Threshold: Threshold{Value: 10000, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: createdAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: snapshot, CurrentSnapshot: snapshot, Comparison: comparison, EvaluatedAt: createdAt})
	if err != nil || evaluation.Summary.Passed != 1 || evaluation.Decisions[0].ObservedValue != 10000 {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
	if _, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "invalid-units", Version: 1, Rules: []PolicyRule{{ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 1, Unit: UnitCount}, Effect: EffectFail}}}); err == nil {
		t.Fatal("expected coverage count-unit rejection")
	}
}

func TestEvaluateFailsRequiredRuleWhenCoverageIsUnknown(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	snapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "required-coverage", Version: 1, Rules: []PolicyRule{{ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 8000, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: createdAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := regression.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: snapshot, CurrentSnapshot: snapshot, Comparison: comparison, EvaluatedAt: createdAt})
	if err != nil || evaluation.Summary.Failed != 1 || evaluation.Decisions[0].Status != StatusFail {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
}

func TestActionsKeepSeparateProvenanceForDifferentBaselines(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	baselineOne, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, EndpointIDs: []string{"endpoint-one"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	baselineTwo, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Minute), EndpointIDs: []string{"endpoint-two"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(2 * time.Minute), EndpointIDs: []string{"endpoint-current"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: 1, Rules: []PolicyRule{{ID: "regression", Type: RuleRegression, Operator: OperatorMaximum, Threshold: Threshold{Value: 0, Unit: UnitCount}, Effect: EffectFail}}})
	if err != nil {
		t.Fatal(err)
	}
	evaluate := func(baselineSnapshot regression.Snapshot) ControlEvaluation {
		comparison, err := regression.Compare(baselineSnapshot, current)
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: current.CreatedAt})
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err := Evaluate(EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: current, Comparison: comparison, EvaluatedAt: current.CreatedAt})
		if err != nil {
			t.Fatal(err)
		}
		return evaluation
	}
	first, second := evaluate(baselineOne), evaluate(baselineTwo)
	if len(first.Actions) != 1 || len(second.Actions) != 1 || first.Actions[0].ID == second.Actions[0].ID {
		t.Fatalf("actions must retain distinct evaluation provenance: first=%+v second=%+v", first.Actions, second.Actions)
	}
}

func TestParsePolicyRejectsUnknownFieldsDuplicateRulesAndSecretLikeValues(t *testing.T) {
	for _, document := range []string{
		`{"project_id":"alpha","name":"policy","version":1,"rules":[{"id":"rule","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"}],"unexpected":true}`,
		`{"project_id":"alpha","name":"policy","version":1,"rules":[{"id":"rule","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"},{"id":"rule","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"}]}`,
		`{"project_id":"alpha","name":"token=opaque","version":1,"rules":[{"id":"rule","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"}]}`,
	} {
		if _, err := ParsePolicy([]byte(document)); err == nil {
			t.Fatalf("expected policy rejection: %s", document)
		}
	}
}

func TestParsePolicyAcceptsStrictBoundedJSON(t *testing.T) {
	policy, err := ParsePolicy([]byte(`{"project_id":"alpha","name":"policy","version":1,"rules":[{"id":"coverage","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"}]}`))
	if err != nil || policy.ProjectID != "alpha" || policy.Fingerprint == "" || len(policy.Rules) != 1 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}
