package governance

import (
	"testing"
	"time"
)

func FuzzTransitionRejectsMalformedOperatorInputWithoutPanic(f *testing.F) {
	f.Add("operator-a", "reviewed documented regression", "acknowledged")
	f.Add("Authorization: Bearer opaque", "reason", "acknowledged")
	f.Add("operator-a", "token=opaque", "completed")
	f.Fuzz(func(t *testing.T, actor, reason, next string) {
		now := time.Unix(1, 0).UTC()
		state, err := NewRecommendationState(StateInput{ProjectID: "alpha", RecommendationID: fingerprintValue("recommendation"), EvaluationFingerprint: fingerprintValue("evaluation"), PolicyFingerprint: fingerprintValue("policy"), BaselineFingerprint: fingerprintValue("baseline"), RecommendationFingerprint: fingerprintValue("payload"), UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationState(next), Actor: actor, Reason: reason, At: now.Add(time.Second)})
	})
}

func FuzzDeriveStatusRejectsMalformedReferenceSetsWithoutPanic(f *testing.F) {
	f.Add("alpha", int64(60), true, false)
	f.Add("token=opaque", int64(-1), false, true)
	f.Fuzz(func(t *testing.T, projectID string, maximumAgeSeconds int64, policyFailed, regressionDetected bool) {
		if maximumAgeSeconds < -3600 || maximumAgeSeconds > 3600 {
			return
		}
		now := time.Unix(1, 0).UTC()
		_, _ = DeriveStatus(StatusInput{ProjectID: projectID, PolicyFingerprint: fingerprintValue("policy"), BaselineFingerprint: fingerprintValue("baseline"), EvaluationFingerprint: fingerprintValue("evaluation"), CurrentSnapshotFingerprint: fingerprintValue("snapshot"), ComparisonFingerprint: fingerprintValue("comparison"), EvaluationAt: now, AsOf: now, MaximumAge: time.Duration(maximumAgeSeconds) * time.Second, PolicyFailed: policyFailed, RegressionDetected: regressionDetected, EvidenceFreshnessKnown: true})
	})
}
