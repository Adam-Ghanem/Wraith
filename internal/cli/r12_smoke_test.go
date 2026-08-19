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

type r12SmokeFixture struct {
	project, databasePath, endpointID string
}

func newR12SmokeFixture(t *testing.T) r12SmokeFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r12-smoke.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	asset, err := evidence.NewWebAsset("alpha", evidence.AssetKindURL, "https://alpha.test", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://alpha.test/api/items?page=1", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "page", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertParameter(ctx, parameter); err != nil {
		t.Fatal(err)
	}
	other, err := evidence.NewWebAsset("beta", evidence.AssetKindURL, "https://beta.test", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, other); err != nil {
		t.Fatal(err)
	}
	return r12SmokeFixture{project: "alpha", databasePath: path, endpointID: endpoint.Identity}
}

func runR12SmokeCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), args, &stdout, &stderr)
	return stdout.String(), err
}

func TestR12LocalCommandSmokeAndAuthorizationMatrix(t *testing.T) {
	fixture := newR12SmokeFixture(t)
	if _, err := runR12SmokeCommand(t, "endpoints", "--project", fixture.project, "--db", fixture.databasePath, "--json"); err == nil {
		t.Fatal("expected endpoints command to require explicit authorization")
	}
	endpoints, err := runR12SmokeCommand(t, "endpoints", "--project", fixture.project, "--authorized", "--db", fixture.databasePath, "--json")
	if err != nil || !strings.Contains(endpoints, fixture.endpointID) || strings.Contains(endpoints, "beta.test") {
		t.Fatalf("endpoints=%s err=%v", endpoints, err)
	}
	surface, err := runR12SmokeCommand(t, "surface", "--project", fixture.project, "--db", fixture.databasePath, "--output", "json")
	if err != nil || !strings.Contains(surface, `"project_id":"alpha"`) || strings.Contains(surface, "beta.test") {
		t.Fatalf("surface=%s err=%v", surface, err)
	}
	campaign, err := runR12SmokeCommand(t, "campaign", "plan", "--project", fixture.project, "--db", fixture.databasePath, "--dry-run", "--output", "json")
	if err != nil || !strings.Contains(campaign, `"task_count"`) || !strings.Contains(campaign, "Dry-run") {
		t.Fatalf("campaign=%s err=%v", campaign, err)
	}
	findings, err := runR12SmokeCommand(t, "findings", "--project", fixture.project, "--db", fixture.databasePath, "--output", "json")
	if err != nil || findings != "[]\n" {
		t.Fatalf("findings=%q err=%v", findings, err)
	}
}
