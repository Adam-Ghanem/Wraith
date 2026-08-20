package governance

import (
	"testing"
	"time"
)

func BenchmarkTransitionAndDeriveStatus(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	state, err := NewRecommendationState(StateInput{ProjectID: "alpha", RecommendationID: fingerprintValue("recommendation"), EvaluationFingerprint: fingerprintValue("evaluation"), PolicyFingerprint: fingerprintValue("policy"), BaselineFingerprint: fingerprintValue("baseline"), RecommendationFingerprint: fingerprintValue("payload"), UpdatedAt: now})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		result, err := Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed documented regression", At: now.Add(time.Second)})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DeriveStatus(StatusInput{ProjectID: "alpha", PolicyFingerprint: result.State.PolicyFingerprint, BaselineFingerprint: result.State.BaselineFingerprint, EvaluationFingerprint: result.State.EvaluationFingerprint, CurrentSnapshotFingerprint: fingerprintValue("snapshot"), ComparisonFingerprint: fingerprintValue("comparison"), EvaluationAt: now, AsOf: now, EvidenceFreshnessKnown: true, Recommendations: []RecommendationGovernanceState{result.State}}); err != nil {
			b.Fatal(err)
		}
	}
}
