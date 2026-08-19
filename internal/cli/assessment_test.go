package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPentestAssessmentPlanIsAuthorizedAndNoNetwork(t *testing.T) {
	args := []string{"pentest", "assessment", "plan", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--max-requests", "8", "--max-duration", "1m", "--max-concurrency", "1", "--rate", "1", "--json"}
	var output bytes.Buffer
	if err := Run(context.Background(), args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"assessment_id"`) || !strings.Contains(output.String(), `"profile":"safe"`) || strings.Contains(output.String(), "cookie") {
		t.Fatalf("output=%s", output.String())
	}
	args = []string{"pentest", "assessment", "plan", "https://app.test", "--project", "alpha", "--scope-version", "scope-v1"}
	if err := Run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected explicit authorization rejection")
	}
}

func TestPentestAssessmentRunDryRunUsesPersistedR1ScopeWithoutExecutionWrites(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	scope := policy.ProjectScope{
		VersionID:     "scope-v1",
		ProjectID:     "alpha",
		Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()},
		Rules:         []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: "https://app.test", CreatedAt: time.Now().UTC()}},
	}
	if err := database.SaveProjectScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--dry-run", "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"dry_run":true`) || strings.Contains(output.String(), "token") {
		t.Fatalf("output=%s", output.String())
	}
	verified, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	runs, err := verified.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs=%#v err=%v, want dry-run without execution lifecycle writes", runs, err)
	}
}

func TestPentestAssessmentRunPersistsFailClosedUnwiredOwnerLifecycle(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment-run.db")
	seedAssessmentScope(t, ctx, databasePath)
	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"partial"`) || strings.Contains(output.String(), "secret-value") {
		t.Fatalf("output=%s", output.String())
	}
	verified, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	runs, err := verified.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 1 || runs[0].Status != "partial" {
		t.Fatalf("runs=%#v err=%v, want one partial fail-closed run", runs, err)
	}
	events, err := verified.ListPentestEvents(ctx, "alpha", runs[0].RunID)
	if err != nil || len(events) == 0 || events[0].MetadataJSON != "{}" {
		t.Fatalf("events=%#v err=%v, want persisted secret-free events", events, err)
	}
}

func TestPentestAssessmentRunDryRunLimitsDependencyClosedTaskPrefix(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment-limit.db")
	seedAssessmentScope(t, ctx, databasePath)
	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--dry-run", "--max-tasks", "1", "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tasks []json.RawMessage `json:"tasks"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Tasks) != 1 {
		t.Fatalf("result=%#v err=%v, want one limited task: %s", result, err, output.String())
	}
}

func seedAssessmentScope(t *testing.T, ctx context.Context, databasePath string) {
	t.Helper()
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	scope := policy.ProjectScope{
		VersionID:     "scope-v1",
		ProjectID:     "alpha",
		Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()},
		Rules:         []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: "https://app.test", CreatedAt: time.Now().UTC()}},
	}
	if err := database.SaveProjectScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
}
