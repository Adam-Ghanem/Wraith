package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

func TestDataGovernancePolicyAndRetentionAreProjectScopedAndRevalidated(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "governance-authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy := storageGovernancePolicy(t, now)
	if err := database.SaveDataGovernancePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.LoadDataGovernancePolicy(ctx, "project-a", policy.Version)
	if err != nil || loaded.Fingerprint != policy.Fingerprint {
		t.Fatalf("LoadDataGovernancePolicy() policy=%#v err=%v", loaded, err)
	}
	if _, err := database.LoadDataGovernancePolicy(ctx, "project-b", policy.Version); err == nil {
		t.Fatal("cross-project policy read unexpectedly succeeded")
	}
	policies, err := database.ListDataGovernancePolicies(ctx, "project-a")
	if err != nil || len(policies) != 1 || policies[0].Fingerprint != policy.Fingerprint {
		t.Fatalf("ListDataGovernancePolicies() policies=%#v err=%v", policies, err)
	}
	if policies, err := database.ListDataGovernancePolicies(ctx, "project-b"); err != nil || len(policies) != 0 {
		t.Fatalf("cross-project policy list policies=%#v err=%v", policies, err)
	}
	retention, err := datagovernance.NewRetentionRecord(datagovernance.RetentionInput{ProjectID: "project-a", Policy: policy, SubjectReference: "evidence-1", CreatedAt: now, RetainUntil: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDataRetentionRecord(ctx, retention); err != nil {
		t.Fatal(err)
	}
	records, err := database.ListDataRetentionRecords(ctx, "project-a")
	if err != nil || len(records) != 1 || records[0].Fingerprint != retention.Fingerprint {
		t.Fatalf("ListDataRetentionRecords() records=%#v err=%v", records, err)
	}
	if records, err := database.ListDataRetentionRecords(ctx, "project-b"); err != nil || len(records) != 0 {
		t.Fatalf("cross-project retention list records=%#v err=%v", records, err)
	}
}

func TestSaveDataGovernancePolicyRejectsForgedFingerprint(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "governance-forged.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	policy := storageGovernancePolicy(t, time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC))
	policy.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := database.SaveDataGovernancePolicy(ctx, policy); !errors.Is(err, datagovernance.ErrGovernanceIntegrityFailure) {
		t.Fatalf("forged policy error=%v", err)
	}
}

func TestDecodeGovernanceRulesRejectsTrailingData(t *testing.T) {
	_, err := decodeGovernanceRules(`[{"consumer":"audit_log","maximum_classification":"internal","retention":3600000000000}] trailing`)
	if !errors.Is(err, datagovernance.ErrGovernanceIntegrityFailure) {
		t.Fatalf("trailing rule data error=%v", err)
	}
}

func storageGovernancePolicy(t testing.TB, now time.Time) datagovernance.Policy {
	t.Helper()
	policy, err := datagovernance.NewPolicy(datagovernance.PolicyInput{ProjectID: "project-a", Version: "policy-v1", CreatedAt: now, Rules: []datagovernance.Rule{
		{Consumer: datagovernance.ConsumerLocalStorage, Maximum: dataclassification.LevelSensitive, Retention: 30 * 24 * time.Hour},
		{Consumer: datagovernance.ConsumerAuditLog, Maximum: dataclassification.LevelInternal, Retention: 30 * 24 * time.Hour},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
