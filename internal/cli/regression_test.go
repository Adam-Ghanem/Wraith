package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestRegressionCompareAndCheckUseOfflineProjectScopedSnapshots(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "regression-cli.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 2, 0, 0, 0, time.UTC)
	baseline, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, EndpointIDs: []string{"endpoint-a"}, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Hour), EndpointIDs: []string{"endpoint-a", "endpoint-b"}, Coverage: regression.Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []regression.Snapshot{baseline, current} {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.SaveRegressionSnapshot(ctx, storage.RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: snapshot.Fingerprint, CampaignID: "campaign", ScopeVersion: "scope-v1", SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"regression", "compare", "--project", "alpha", "--baseline", baseline.Fingerprint, "--current", current.Fingerprint, "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"change_type":"new_endpoint"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	err = Run(ctx, []string{"regression", "check", "--project", "alpha", "--baseline", baseline.Fingerprint, "--current", current.Fingerprint, "--fail-on", "informational", "--db", path}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrRegressionDetected) {
		t.Fatalf("expected deterministic regression detection, got %v", err)
	}
	if err := Run(ctx, []string{"regression", "compare", "--project", "beta", "--baseline", baseline.Fingerprint, "--current", current.Fingerprint, "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("cross-project comparison was accepted")
	}
}

func TestRegressionSnapshotPersistsDeterministicCampaignReference(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "regression-snapshot-cli.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 3, 0, 0, 0, time.UTC)
	if err := database.CreateCampaign(ctx, storage.CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.test", AssessmentPlanJSON: `{"plan":1}`, SurfaceSnapshotID: "surface-1", SurfaceFingerprint: "surface-fingerprint", SurfaceSourceVersion: "r11.6-v1", Status: "completed", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"regression", "snapshot", "--project", "alpha", "--campaign", "campaign-1", "--persist", "--format", "json", "--db", path}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"project_id":"alpha"`) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}
