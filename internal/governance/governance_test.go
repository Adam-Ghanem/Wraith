package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestTransitionCreatesDeterministicStateAndAuditLineage(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 9, 0, 0, 0, time.UTC)
	state, err := NewRecommendationState(StateInput{
		ProjectID:                 "alpha",
		RecommendationID:          fingerprintValue("recommendation"),
		EvaluationFingerprint:     fingerprintValue("evaluation"),
		PolicyFingerprint:         fingerprintValue("policy"),
		BaselineFingerprint:       fingerprintValue("baseline"),
		RecommendationFingerprint: fingerprintValue("recommendation-payload"),
		UpdatedAt:                 createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed documented regression", At: createdAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed documented regression", At: createdAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if first.State.State != RecommendationAcknowledged || first.Decision.PreviousStateFingerprint != state.Fingerprint || first.Decision.ResultingStateFingerprint != first.State.Fingerprint {
		t.Fatalf("unexpected transition lineage: %+v", first)
	}
	if first.Decision.Fingerprint != second.Decision.Fingerprint || first.Event.Fingerprint != second.Event.Fingerprint || first.State.Fingerprint != second.State.Fingerprint {
		t.Fatalf("identical transitions must be deterministic: first=%+v second=%+v", first, second)
	}
}

func TestTransitionRejectsInvalidLifecycleAndSecretReason(t *testing.T) {
	now := time.Date(2026, time.August, 20, 9, 0, 0, 0, time.UTC)
	state, err := NewRecommendationState(StateInput{ProjectID: "alpha", RecommendationID: fingerprintValue("recommendation"), EvaluationFingerprint: fingerprintValue("evaluation"), PolicyFingerprint: fingerprintValue("policy"), BaselineFingerprint: fingerprintValue("baseline"), RecommendationFingerprint: fingerprintValue("recommendation-payload"), UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationCompleted, Actor: "operator-a", Reason: "skip lifecycle", At: now}); err == nil {
		t.Fatal("expected invalid transition rejection")
	}
	if _, err := Transition(TransitionInput{State: state, ExpectedState: RecommendationRecommended, NextState: RecommendationAcknowledged, Actor: "operator-a", Reason: "Authorization: Bearer secret-value", At: now}); err == nil {
		t.Fatal("expected secret-bearing rationale rejection")
	}
}

func TestDeriveStatusPreservesStalenessAndUnknownLimits(t *testing.T) {
	now := time.Date(2026, time.August, 20, 10, 0, 0, 0, time.UTC)
	status, err := DeriveStatus(StatusInput{ProjectID: "alpha", PolicyFingerprint: fingerprintValue("policy"), BaselineFingerprint: fingerprintValue("baseline"), EvaluationFingerprint: fingerprintValue("evaluation"), CurrentSnapshotFingerprint: fingerprintValue("snapshot"), ComparisonFingerprint: fingerprintValue("comparison"), EvaluationAt: now.Add(-2 * time.Hour), AsOf: now, MaximumAge: time.Hour, PolicyFailed: false, RegressionDetected: false, EvidenceFreshnessKnown: false})
	if err != nil {
		t.Fatal(err)
	}
	if status.Overall != AssessmentStale || !contains(status.StaleReasons, "evaluation_max_age_exceeded") || !contains(status.Limitations, "evidence_freshness_unknown") {
		t.Fatalf("unexpected derived governance status: %+v", status)
	}
}

func fingerprintValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
