package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRegressionSnapshotsAndComparisonsAreProjectIsolatedIdempotentAndRestartSafe(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r18.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 1, 0, 0, 0, time.UTC)
	baseline := RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: "snapshot-baseline", CampaignID: "campaign-baseline", ScopeVersion: "scope-v1", SnapshotFingerprint: repeatHex("a"), SnapshotJSON: `{"project_id":"alpha"}`, CreatedAt: createdAt}
	current := RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: "snapshot-current", CampaignID: "campaign-current", ScopeVersion: "scope-v1", SnapshotFingerprint: repeatHex("b"), SnapshotJSON: `{"project_id":"alpha"}`, CreatedAt: createdAt.Add(time.Hour)}
	for _, record := range []RegressionSnapshotRecord{baseline, current, baseline} {
		if err := database.SaveRegressionSnapshot(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	comparison := RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baseline.SnapshotID, CurrentSnapshotID: current.SnapshotID, Fingerprint: repeatHex("c"), ComparisonJSON: `{"project_id":"alpha"}`, CreatedAt: createdAt.Add(2 * time.Hour)}
	if err := database.SaveRegressionComparison(ctx, comparison); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveRegressionComparison(ctx, comparison); err != nil {
		t.Fatal(err)
	}
	if _, err := database.LoadRegressionSnapshot(ctx, "beta", baseline.SnapshotID); err == nil {
		t.Fatal("expected cross-project snapshot read rejection")
	}
	comparisons, err := database.ListRegressionComparisons(ctx, "alpha")
	if err != nil || len(comparisons) != 1 || comparisons[0].Fingerprint != comparison.Fingerprint {
		t.Fatalf("comparisons=%+v err=%v", comparisons, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.LoadRegressionSnapshot(ctx, "alpha", baseline.SnapshotID)
	if err != nil || loaded.SnapshotFingerprint != baseline.SnapshotFingerprint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
