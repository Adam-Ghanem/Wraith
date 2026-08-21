package dataprotection

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

func TestAggregateClassificationUsesDeterministicMaximum(t *testing.T) {
	classification, err := AggregateClassification(dataclassification.LevelPublic, dataclassification.LevelInternal, dataclassification.LevelRestricted)
	if err != nil || classification != dataclassification.LevelRestricted {
		t.Fatalf("AggregateClassification() classification=%q err=%v", classification, err)
	}
	if _, err := AggregateClassification(dataclassification.Level("unknown")); !errors.Is(err, ErrClassificationInvalid) {
		t.Fatalf("unknown classification error=%v", err)
	}
}

func TestEvaluateRequiresValidT7GovernanceAndProtectsExecutiveRestrictedData(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := testPolicy(t, now)
	governance, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: policy, ProjectID: "project-a", Subject: datagovernance.SubjectEvidence, Classification: dataclassification.LevelRestricted, Consumer: datagovernance.ConsumerExecutiveReport, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := NewDescriptor(DescriptorInput{ProjectID: "project-a", ObjectType: ObjectEvidence, ObjectID: "evidence-1", Classification: dataclassification.LevelRestricted, SourceReference: "observation-1", ScopeReference: "scope-v1", GovernancePolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Evaluate(EvaluationInput{Descriptor: descriptor, Profile: ProfileExecutiveOutput, Policy: policy, GovernanceDecision: governance, OccurredAt: now})
	if err != nil || decision.Action != ActionMetadataOnly || !decision.RedactionRequired || decision.ReasonCode != "profile_restricted_metadata_only" {
		t.Fatalf("Evaluate() decision=%#v err=%v", decision, err)
	}
	if err := ValidateDecision(decision); err != nil {
		t.Fatalf("ValidateDecision() error=%v", err)
	}
}

func TestEvaluateFailsClosedOnForgedDescriptorAndMissingGovernance(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := testPolicy(t, now)
	descriptor, err := NewDescriptor(DescriptorInput{ProjectID: "project-a", ObjectType: ObjectFinding, ObjectID: "finding-1", Classification: dataclassification.LevelInternal, SourceReference: "evidence-1", ScopeReference: "scope-v1", GovernancePolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(EvaluationInput{Descriptor: descriptor, Profile: ProfileTechnicalOutput, Policy: policy, OccurredAt: now}); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("missing governance error=%v", err)
	}
	descriptor.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := Evaluate(EvaluationInput{Descriptor: descriptor, Profile: ProfileTechnicalOutput, Policy: policy, OccurredAt: now}); !errors.Is(err, ErrIntegrityFailure) {
		t.Fatalf("forged descriptor error=%v", err)
	}
}

func TestRedactIsDeterministicAndIdempotent(t *testing.T) {
	first, err := Redact("Authorization: Bearer example-token")
	if err != nil || first != dataclassification.RedactedValue {
		t.Fatalf("Redact() value=%q err=%v", first, err)
	}
	second, err := Redact(first)
	if err != nil || second != first {
		t.Fatalf("Redact(Redact()) value=%q err=%v", second, err)
	}
}

func testPolicy(t testing.TB, now time.Time) datagovernance.Policy {
	t.Helper()
	policy, err := datagovernance.NewPolicy(datagovernance.PolicyInput{ProjectID: "project-a", Version: "policy-v1", CreatedAt: now, Rules: []datagovernance.Rule{
		{Consumer: datagovernance.ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: 24 * time.Hour},
		{Consumer: datagovernance.ConsumerExecutiveReport, Maximum: dataclassification.LevelInternal, Retention: 24 * time.Hour},
		{Consumer: datagovernance.ConsumerLocalStorage, Maximum: dataclassification.LevelSensitive, Retention: 24 * time.Hour},
		{Consumer: datagovernance.ConsumerAuditLog, Maximum: dataclassification.LevelInternal, Retention: 24 * time.Hour},
		{Consumer: datagovernance.ConsumerJSONExport, Maximum: dataclassification.LevelInternal, Retention: 24 * time.Hour},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
