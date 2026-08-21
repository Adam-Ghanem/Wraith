package dataprotection

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

func TestNewSnapshotIsImmutableAndRejectsForgedFingerprint(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := testPolicy(t, now)
	governance, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: policy, ProjectID: "project-a", Subject: datagovernance.SubjectEvidence, Classification: dataclassification.LevelInternal, Consumer: datagovernance.ConsumerTechnicalReport, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := NewDescriptor(DescriptorInput{ProjectID: "project-a", ObjectType: ObjectEvidence, ObjectID: "evidence-1", Classification: dataclassification.LevelInternal, SourceReference: "observation-1", ScopeReference: "scope-v1", GovernancePolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Evaluate(EvaluationInput{Descriptor: descriptor, Profile: ProfileTechnicalOutput, Policy: policy, GovernanceDecision: governance, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewSnapshot(SnapshotInput{ProjectID: "project-a", SnapshotID: "snapshot-1", Descriptor: descriptor, Decision: decision, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("ValidateSnapshot() error=%v", err)
	}
	snapshot.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := ValidateSnapshot(snapshot); !errors.Is(err, ErrIntegrityFailure) {
		t.Fatalf("forged snapshot error=%v", err)
	}
}
