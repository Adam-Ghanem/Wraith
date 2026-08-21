package datagovernance

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

func TestNewPolicyCanonicalizesAndRejectsDuplicateRules(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy, err := NewPolicy(PolicyInput{
		ProjectID: "project-a",
		Version:   "governance-v1",
		CreatedAt: now,
		Rules: []Rule{
			{Consumer: ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: 30 * 24 * time.Hour},
			{Consumer: ConsumerExecutiveReport, Maximum: dataclassification.LevelInternal, Retention: 7 * 24 * time.Hour},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if policy.Fingerprint == "" || policy.PolicyVersion != PolicyVersion || len(policy.Rules) != 2 {
		t.Fatalf("NewPolicy() = %#v", policy)
	}
	if err := ValidatePolicy(policy); err != nil {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}

	_, err = NewPolicy(PolicyInput{ProjectID: "project-a", Version: "governance-v1", CreatedAt: now, Rules: []Rule{
		{Consumer: ConsumerAuditLog, Maximum: dataclassification.LevelInternal, Retention: time.Hour},
		{Consumer: ConsumerAuditLog, Maximum: dataclassification.LevelInternal, Retention: time.Hour},
	}})
	if !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("duplicate rule error = %v, want ErrPolicyInvalid", err)
	}
}

func TestEvaluateFailsClosedForForgedPolicyCrossProjectAndExecutiveRestrictedData(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := mustPolicy(t, now)
	forged := policy
	forged.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := Evaluate(EvaluationInput{Policy: forged, ProjectID: "project-a", Subject: SubjectEvidence, Classification: dataclassification.LevelInternal, Consumer: ConsumerTechnicalReport, OccurredAt: now}); !errors.Is(err, ErrGovernanceIntegrityFailure) {
		t.Fatalf("forged policy error = %v, want ErrGovernanceIntegrityFailure", err)
	}
	if _, err := Evaluate(EvaluationInput{Policy: policy, ProjectID: "project-b", Subject: SubjectEvidence, Classification: dataclassification.LevelInternal, Consumer: ConsumerTechnicalReport, OccurredAt: now}); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project error = %v, want ErrProjectMismatch", err)
	}
	decision, err := Evaluate(EvaluationInput{Policy: policy, ProjectID: "project-a", Subject: SubjectEvidence, Classification: dataclassification.LevelRestricted, Consumer: ConsumerExecutiveReport, OccurredAt: now})
	if err != nil || decision.Action != DecisionAllowMetadataOnly || decision.ReasonCode != "consumer_classification_restricted" {
		t.Fatalf("restricted executive decision=%#v err=%v", decision, err)
	}
}

func TestRetentionEvaluationRespectsHoldAndExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := mustPolicy(t, now)
	active, err := NewRetentionRecord(RetentionInput{ProjectID: "project-a", Policy: policy, SubjectReference: "evidence-1", CreatedAt: now, RetainUntil: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := EvaluateRetention(active, now); err != nil || status != RetentionActive {
		t.Fatalf("active retention status=%q err=%v", status, err)
	}
	held := active
	held.Hold = true
	held.Fingerprint = retentionFingerprint(held)
	if status, err := EvaluateRetention(held, now.Add(24*time.Hour)); err != nil || status != RetentionHeld {
		t.Fatalf("held retention status=%q err=%v", status, err)
	}
	if status, err := EvaluateRetention(active, now.Add(2*time.Hour)); err != nil || status != RetentionDeletionEligible {
		t.Fatalf("expired retention status=%q err=%v", status, err)
	}
}

func TestValidateDecisionRejectsForgedFingerprint(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	decision, err := Evaluate(EvaluationInput{Policy: mustPolicy(t, now), ProjectID: "project-a", Subject: SubjectEvidence, Classification: dataclassification.LevelSensitive, Consumer: ConsumerTechnicalReport, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDecision(decision); err != nil {
		t.Fatalf("ValidateDecision() error = %v", err)
	}
	decision.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := ValidateDecision(decision); !errors.Is(err, ErrGovernanceIntegrityFailure) {
		t.Fatalf("forged decision error = %v, want ErrGovernanceIntegrityFailure", err)
	}
}

func mustPolicy(t testing.TB, now time.Time) Policy {
	t.Helper()
	policy, err := NewPolicy(PolicyInput{ProjectID: "project-a", Version: "governance-v1", CreatedAt: now, Rules: []Rule{
		{Consumer: ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: 30 * 24 * time.Hour},
		{Consumer: ConsumerExecutiveReport, Maximum: dataclassification.LevelInternal, Retention: 7 * 24 * time.Hour},
		{Consumer: ConsumerAuditLog, Maximum: dataclassification.LevelInternal, Retention: 30 * 24 * time.Hour},
		{Consumer: ConsumerLocalStorage, Maximum: dataclassification.LevelSensitive, Retention: 30 * 24 * time.Hour},
		{Consumer: ConsumerEgress, Maximum: dataclassification.LevelInternal, Retention: 24 * time.Hour},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
