package continuousassessment

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

func FuzzParsePolicyRejectsMalformedOrUnsafeDocuments(f *testing.F) {
	f.Add(`{"project_id":"alpha","name":"policy","version":1,"rules":[{"id":"coverage","type":"coverage","operator":"minimum","threshold":{"value":8000,"unit":"basis_points"},"effect":"fail"}]}`)
	f.Add(`{"project_id":"alpha","name":"token=opaque","version":1,"rules":[]}`)
	f.Add(`{`)
	f.Fuzz(func(t *testing.T, document string) {
		_, _ = ParsePolicy([]byte(document))
	})
}

func FuzzEvaluateDoesNotPanicOnRejectedOrNormalizedInputs(f *testing.F) {
	f.Add("alpha", "endpoint-before", "endpoint-after", 0, 10000)
	f.Add("token=opaque", "endpoint-before", "endpoint-after", -1, 10001)
	f.Fuzz(func(t *testing.T, projectID, baselineEndpoint, currentEndpoint string, threshold, coverage int) {
		now := time.Unix(1, 0).UTC()
		baselineSnapshot, baselineErr := regression.NewSnapshot(regression.SnapshotInput{ProjectID: projectID, ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: now, EndpointIDs: []string{baselineEndpoint}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
		currentSnapshot, currentErr := regression.NewSnapshot(regression.SnapshotInput{ProjectID: projectID, ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: now.Add(time.Second), EndpointIDs: []string{currentEndpoint}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
		policy, policyErr := NewPolicy(PolicyInput{ProjectID: projectID, Name: "policy", Version: PolicyVersion, Rules: []PolicyRule{{ID: "regression", Type: RuleRegression, Operator: OperatorMaximum, Threshold: Threshold{Value: threshold, Unit: UnitCount}, Effect: EffectFail}}})
		if baselineErr != nil || currentErr != nil || policyErr != nil || coverage < 0 || coverage > 10000 {
			return
		}
		comparison, err := regression.Compare(baselineSnapshot, currentSnapshot)
		if err != nil {
			return
		}
		baseline, err := NewBaseline(BaselineInput{ProjectID: projectID, SnapshotFingerprint: baselineSnapshot.Fingerprint, SnapshotCreatedAt: baselineSnapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CreatedAt: now})
		if err != nil {
			return
		}
		_, _ = Evaluate(EvaluationInput{ProjectID: projectID, Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: now})
	})
}
