package continuousassessment

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

func BenchmarkEvaluatePolicyAgainstR18Comparison(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	baselineSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: now, Findings: []regression.Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "low", RiskBand: "low", Status: "open"}}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 10, Denominator: 10}})
	if err != nil {
		b.Fatal(err)
	}
	currentSnapshot, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: now.Add(time.Second), EndpointIDs: []string{"endpoint-1"}, Findings: []regression.Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "high", RiskBand: "high", Status: "open"}}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 8, Denominator: 10}})
	if err != nil {
		b.Fatal(err)
	}
	comparison, err := regression.Compare(baselineSnapshot, currentSnapshot)
	if err != nil {
		b.Fatal(err)
	}
	policy, err := NewPolicy(PolicyInput{ProjectID: "alpha", Name: "policy", Version: PolicyVersion, Rules: []PolicyRule{{ID: "regression", Type: RuleRegression, Operator: OperatorMaximum, Threshold: Threshold{Value: 0, Unit: UnitCount}, Effect: EffectFail}, {ID: "coverage", Type: RuleCoverage, Operator: OperatorMinimum, Threshold: Threshold{Value: 9000, Unit: UnitBasisPoints}, Effect: EffectFail}}})
	if err != nil {
		b.Fatal(err)
	}
	baseline, err := NewBaseline(BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		b.Fatal(err)
	}
	input := EvaluationInput{ProjectID: "alpha", Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: now}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Evaluate(input); err != nil {
			b.Fatal(err)
		}
	}
}
