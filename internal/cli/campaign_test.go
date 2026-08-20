package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPentestCampaignCreateAndStatusPersistBoundedLocalState(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "campaign-cli.db")
	seedAssessmentScope(t, ctx, databasePath)
	createArgs := []string{"pentest", "campaign", "create", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--json"}
	var created bytes.Buffer
	if err := Run(ctx, createArgs, &created, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var output struct {
		CampaignID string `json:"campaign_id"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(created.Bytes(), &output); err != nil || output.CampaignID == "" || output.Status != "ready" {
		t.Fatalf("output=%s decoded=%#v err=%v", created.String(), output, err)
	}
	var status bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "status", output.CampaignID, "--project", "alpha", "--db", databasePath, "--json"}, &status, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(status.Bytes(), []byte(`"campaign_id":"`+output.CampaignID+`"`)) || !bytes.Contains(status.Bytes(), []byte(`"surface_snapshot_id"`)) {
		t.Fatalf("status=%s", status.String())
	}
}

func TestPentestCampaignRunPersistsPartialFailClosedCycle(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "campaign-run.db")
	seedAssessmentScope(t, ctx, databasePath)
	var created bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "create", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--json"}, &created, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var createOutput struct {
		CampaignID string `json:"campaign_id"`
	}
	if err := json.Unmarshal(created.Bytes(), &createOutput); err != nil || createOutput.CampaignID == "" {
		t.Fatalf("created=%s err=%v", created.String(), err)
	}
	var run bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "run", createOutput.CampaignID, "--project", "alpha", "--authorized", "--db", databasePath, "--json"}, &run, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(run.Bytes(), []byte(`"status":"partial"`)) || !bytes.Contains(run.Bytes(), []byte(`"checkpoint_id"`)) {
		t.Fatalf("run=%s", run.String())
	}
	var status bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "status", createOutput.CampaignID, "--project", "alpha", "--db", databasePath, "--json"}, &status, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(status.Bytes(), []byte(`"status":"paused"`)) {
		t.Fatalf("persisted campaign status=%s", status.String())
	}
}

func TestPentestCampaignDryRunCreatesNoCycleOrExecutionLifecycle(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "campaign-dry-run.db")
	seedAssessmentScope(t, ctx, databasePath)
	var created bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "create", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--json"}, &created, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var createOutput struct {
		CampaignID string `json:"campaign_id"`
	}
	if err := json.Unmarshal(created.Bytes(), &createOutput); err != nil {
		t.Fatal(err)
	}
	var dryRun bytes.Buffer
	if err := Run(ctx, []string{"pentest", "campaign", "run", createOutput.CampaignID, "--project", "alpha", "--authorized", "--dry-run", "--db", databasePath, "--json"}, &dryRun, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dryRun.Bytes(), []byte(`"dry_run":true`)) {
		t.Fatalf("dry run=%s", dryRun.String())
	}
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	runs, err := database.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs=%#v err=%v", runs, err)
	}
	record, err := database.LoadCampaign(ctx, "alpha", createOutput.CampaignID)
	if err != nil || record.Status != "ready" || record.LastCheckpointID != "" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}
