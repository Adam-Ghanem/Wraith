package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestRunFuzzDryRunUsesOnlySelectedProjectEvidence(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "wraith.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	endpoint, err := evidence.NewEndpoint("project-a", "GET", "https://example.test/api/users", now)
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("project-a", endpoint, evidence.ParameterLocationQuery, "id", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertParameter(ctx, parameter); err != nil {
		t.Fatal(err)
	}
	other, err := evidence.NewEndpoint("project-b", "GET", "https://example.test/api/users", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	args := []string{"fuzz", "--project", "project-a", "--authorized", "--endpoint", endpoint.Identity, "--parameter", "id", "--location", "query", "--profile", "minimal", "--dry-run", "--db", databasePath, "--json"}
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"dry_run":true`) || !strings.Contains(output.String(), endpoint.Identity) {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	output.Reset()
	args[3] = "project-a"
	args[5] = other.Identity
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err == nil {
		t.Fatal("expected cross-project endpoint rejection")
	}
}
