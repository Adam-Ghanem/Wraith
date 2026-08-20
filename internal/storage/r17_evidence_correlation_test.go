package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestEvidenceCorrelationSnapshotsAreProjectScopedIdempotentAndRestartSafe(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r17.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	record := EvidenceCorrelationSnapshotRecord{ProjectID: "alpha", CampaignID: "campaign-1", FindingID: "finding-1", Fingerprint: "snapshot-fingerprint", VerificationState: "supported", FreshnessState: "current", ReproducibilityState: "single_observation", SnapshotJSON: `{"finding_id":"finding-1","evidence_references":["observation-1"]}`, CreatedAt: time.Unix(1, 0).UTC()}
	if err := database.SaveEvidenceCorrelationSnapshot(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveEvidenceCorrelationSnapshot(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	alpha, err := reopened.ListEvidenceCorrelationSnapshots(ctx, "alpha", "campaign-1")
	if err != nil || len(alpha) != 1 || alpha[0].FindingID != "finding-1" {
		t.Fatalf("alpha=%+v err=%v", alpha, err)
	}
	beta, err := reopened.ListEvidenceCorrelationSnapshots(ctx, "beta", "campaign-1")
	if err != nil || len(beta) != 0 {
		t.Fatalf("beta=%+v err=%v", beta, err)
	}
}
