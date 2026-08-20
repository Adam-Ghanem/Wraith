package storage

import (
	"context"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/decisionintelligence"
)

func TestBuildDecisionSnapshotConsumesVerifiedProjectLocalR18R19R20R21Sources(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()

	snapshot, err := database.BuildDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request})
	if err != nil {
		t.Fatalf("BuildDecisionSnapshot() error = %v", err)
	}
	if !decisionintelligence.ValidateSnapshot(snapshot) || len(snapshot.Candidates) == 0 {
		t.Fatalf("invalid or empty decision snapshot = %+v", snapshot)
	}
	if _, err := database.BuildDecisionSnapshot(ctx, "beta", DecisionRequest{Analytics: request}); err == nil {
		t.Fatal("BuildDecisionSnapshot() accepted a project with no project-local validated source lineage")
	}
}

func TestDecisionSnapshotPersistenceIsImmutableIdempotentAndRejectsForgedCache(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()
	snapshot, err := database.BuildDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDecisionSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("SaveDecisionSnapshot() error = %v", err)
	}
	if err := database.SaveDecisionSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("exact decision replay must be idempotent: %v", err)
	}
	loaded, found, err := database.LoadVerifiedDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request})
	if err != nil || !found || loaded.Fingerprint != snapshot.Fingerprint {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	if _, err := database.sql.ExecContext(ctx, `UPDATE decision_snapshots SET snapshot_json='{}' WHERE project_id=? AND snapshot_fingerprint=?`, "alpha", snapshot.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.LoadVerifiedDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request}); err == nil {
		t.Fatal("expected forged stored decision snapshot rejection")
	}
}

func TestSaveDecisionSnapshotRejectsForgedDerivedCandidate(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	defer database.Close()
	snapshot, err := database.BuildDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Candidates[0].Priority = decisionintelligence.PriorityP4
	if err := database.SaveDecisionSnapshot(ctx, snapshot); err == nil {
		t.Fatal("SaveDecisionSnapshot() accepted a forged candidate priority")
	}
}

func TestDecisionSnapshotRestartSafetyAndStaleSourceRefusal(t *testing.T) {
	ctx := context.Background()
	database, request := analyticsStorageFixture(t, ctx)
	snapshot, err := database.BuildDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDecisionSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	var sequence int
	var name, path string
	if err := database.sql.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil || path == "" {
		t.Fatalf("database path err=%v path=%q", err, path)
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
	if _, found, err := database.LoadVerifiedDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request}); err != nil || !found {
		t.Fatalf("restart-safe cache load found=%t err=%v", found, err)
	}
	if _, err := database.sql.ExecContext(ctx, `UPDATE assessment_evaluations SET evaluation_json='{}' WHERE project_id=?`, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.LoadVerifiedDecisionSnapshot(ctx, "alpha", DecisionRequest{Analytics: request}); err == nil {
		t.Fatal("stale cache must not survive invalid current source state")
	}
}
