package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
	"github.com/Adam-Ghanem/Wraith/internal/dataprotection"
)

func TestDataProtectionSnapshotStorageIsProjectScopedAndRejectsForgery(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	snapshot := testProtectionSnapshot(t, now)
	if err := db.SaveDataProtectionSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDataProtectionSnapshot(ctx, snapshot); !errors.Is(err, ErrDataProtectionSnapshotExists) {
		t.Fatalf("duplicate error=%v", err)
	}
	loaded, err := db.LoadDataProtectionSnapshot(ctx, "project-a", snapshot.SnapshotID)
	if err != nil || loaded.Fingerprint != snapshot.Fingerprint {
		t.Fatalf("LoadDataProtectionSnapshot() snapshot=%#v err=%v", loaded, err)
	}
	if _, err := db.LoadDataProtectionSnapshot(ctx, "project-b", snapshot.SnapshotID); !errors.Is(err, ErrDataProtectionSnapshotNotFound) {
		t.Fatalf("cross-project error=%v", err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE data_protection_snapshots SET fingerprint = ? WHERE project_id = ? AND snapshot_id = ?`, "0000000000000000000000000000000000000000000000000000000000000000", "project-a", snapshot.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LoadDataProtectionSnapshot(ctx, "project-a", snapshot.SnapshotID); !errors.Is(err, dataprotection.ErrIntegrityFailure) {
		t.Fatalf("forged record error=%v", err)
	}
}

func testProtectionSnapshot(t testing.TB, now time.Time) dataprotection.Snapshot {
	t.Helper()
	policy, err := datagovernance.NewPolicy(datagovernance.PolicyInput{ProjectID: "project-a", Version: "policy-v1", CreatedAt: now, Rules: []datagovernance.Rule{{Consumer: datagovernance.ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	governance, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: policy, ProjectID: "project-a", Subject: datagovernance.SubjectEvidence, Classification: dataclassification.LevelInternal, Consumer: datagovernance.ConsumerTechnicalReport, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := dataprotection.NewDescriptor(dataprotection.DescriptorInput{ProjectID: "project-a", ObjectType: dataprotection.ObjectEvidence, ObjectID: "evidence-1", Classification: dataclassification.LevelInternal, SourceReference: "observation-1", ScopeReference: "scope-v1", GovernancePolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := dataprotection.Evaluate(dataprotection.EvaluationInput{Descriptor: descriptor, Profile: dataprotection.ProfileTechnicalOutput, Policy: policy, GovernanceDecision: governance, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := dataprotection.NewSnapshot(dataprotection.SnapshotInput{ProjectID: "project-a", SnapshotID: "snapshot-1", Descriptor: descriptor, Decision: decision, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
