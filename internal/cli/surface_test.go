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

func TestSurfaceAndCampaignPlanCommandsAreLocalAndProjectScoped(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "surface.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	asset, err := evidence.NewWebAsset("alpha", evidence.AssetKindURL, "https://app.test", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://app.test/api/items", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if _, err = database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var surface, campaign bytes.Buffer
	if err := runSurface(ctx, []string{"surface", "--project", "alpha", "--db", path, "--output", "json"}, &surface, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runCampaign(ctx, []string{"campaign", "plan", "--project", "alpha", "--db", path, "--dry-run", "--output", "json"}, &campaign, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(surface.String(), `"project_id":"alpha"`) || !strings.Contains(campaign.String(), `"task_count"`) || strings.Contains(surface.String(), "https://other.test") {
		t.Fatalf("surface=%s campaign=%s", surface.String(), campaign.String())
	}
}
