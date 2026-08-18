package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestParseJSOptionsRequiresAuthorizationProjectAndLocalInput(t *testing.T) {
	if _, err := parseJSOptions([]string{"js", "--project", "project-a", "--file", "app.js"}); err == nil {
		t.Fatal("expected authorization requirement")
	}
	if _, err := parseJSOptions([]string{"js", "--project", "project-a", "--authorized"}); err == nil {
		t.Fatal("expected explicit local source requirement")
	}
	options, err := parseJSOptions([]string{"js", "--project", "project-a", "--authorized", "--file", "app.js", "--asset", "javascript:https://example.test/app.js", "--sourcemap", "app.js.map", "--max-files", "2", "--max-size", "4096", "--json"})
	if err != nil || options.ProjectID != "project-a" || options.FilePath != "app.js" || options.AssetID == "" || options.MaxFiles != 2 || options.MaxSize != 4096 || !options.JSON {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}

func TestRunJSDoesNotReadAnotherProjectsSelectedAsset(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "r6.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	asset, err := evidence.NewWebAsset("project-b", evidence.AssetKindJavaScript, "https://example.test/app.js", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(directory, "app.js")
	if err := os.WriteFile(filePath, []byte(`fetch("/api/users")`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = Run(ctx, []string{"js", "--project", "project-a", "--authorized", "--db", databasePath, "--file", filePath, "--asset", asset.Identity, "--json"}, &output, &bytes.Buffer{})
	if err == nil || output.Len() != 0 {
		t.Fatalf("cross-project asset selection err=%v output=%q", err, output.String())
	}
}

func TestRunJSEmitsJSONAndPersistsSelectedProjectAssetEvidence(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "r6-success.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindJavaScript, "https://example.test/app.js", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(directory, "app.js")
	if err := os.WriteFile(filePath, []byte(`fetch("/api/users?token=secret", {method:"POST"})`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"js", "--project", "project-a", "--authorized", "--db", databasePath, "--file", filePath, "--asset", asset.Identity, "--json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Parsed   bool `json:"parsed"`
		Requests []struct {
			Method string `json:"method"`
			URL    string `json:"url"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Parsed || len(result.Requests) != 1 || result.Requests[0].Method != "POST" || result.Requests[0].URL != "/api/users?token" {
		t.Fatalf("result=%#v raw=%q err=%v", result, output.String(), err)
	}
	database, err = storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	endpoints, err := database.ListEndpoints(ctx, "project-a")
	if err != nil || len(endpoints) != 1 || endpoints[0].Identity != "POST https://example.test/api/users" {
		t.Fatalf("endpoints=%#v err=%v", endpoints, err)
	}
}
