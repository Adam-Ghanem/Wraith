package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestParseContentOptionsRequiresExplicitAuthorizationAndBounds(t *testing.T) {
	_, err := parseContentOptions([]string{"content", "--project", "project-a", "--base-url", "https://example.test", "--wordlist", "local.txt"})
	if err == nil {
		t.Fatal("expected authorization requirement")
	}
	options, err := parseContentOptions([]string{"content", "--project", "project-a", "--authorized", "--base-url", "https://example.test", "--wordlist", "local.txt", "--max-entries", "4", "--max-requests", "5", "--max-duration", "15s", "--concurrency", "1", "--rate", "1", "--depth", "1", "--dry-run"})
	if err != nil || options.ProjectID != "project-a" || !options.DryRun || options.MaxEntries != 4 || options.MaxRequests != 5 || options.MaxRecursionDepth != 1 {
		t.Fatalf("options=%#v err=%v", options, err)
	}
	if _, err := parseContentOptions([]string{"content", "--project", "project-a", "--authorized", "--base-url", "https://example.test", "--wordlist", "local.txt", "--max-entries", "4", "--max-requests", "5", "--max-duration", "15s", "--concurrency", "1", "--rate", "1", "--depth", "3"}); err == nil {
		t.Fatal("expected depth cap")
	}
}

func TestRunDispatchesContentCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"content"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "wraith content") {
		t.Fatalf("err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func TestParseVHostOptionsRequiresExplicitAuthorizationAndSuffix(t *testing.T) {
	_, err := parseVHostOptions([]string{"vhost", "--project", "project-a", "--authorized", "--base-url", "https://example.test", "--wordlist", "local.txt"})
	if err == nil {
		t.Fatal("expected suffix requirement")
	}
	options, err := parseVHostOptions([]string{"vhost", "--project", "project-a", "--authorized", "--base-url", "https://example.test", "--host-suffix", "example.test", "--wordlist", "local.txt", "--max-entries", "4", "--max-requests", "5", "--max-duration", "15s", "--concurrency", "1", "--rate", "1", "--dry-run"})
	if err != nil || options.HostSuffix != "example.test" || !options.DryRun || options.MaxEntries != 4 {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}

func TestRunContentDryRunEnforcesProjectLocalBaseEvidence(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "r75.db")
	wordlistPath := filepath.Join(directory, "content.txt")
	if err := os.WriteFile(wordlistPath, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	foreign, err := evidence.NewEndpoint("project-b", "GET", "https://example.test/", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"content", "--project", "project-a", "--authorized", "--db", databasePath, "--base-url", "https://example.test/", "--wordlist", wordlistPath, "--max-entries", "4", "--max-requests", "5", "--max-duration", "15s", "--concurrency", "1", "--rate", "1", "--dry-run"}
	var stdout bytes.Buffer
	if err := runContent(ctx, args, &stdout, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "selected project") {
		t.Fatalf("cross-project error=%v", err)
	}
	database, err = storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	owned, err := evidence.NewEndpoint("project-a", "GET", "https://example.test/", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, owned); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runContent(ctx, args, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), "dry_run=true") {
		t.Fatalf("dry-run error=%v output=%q", err, stdout.String())
	}
}

func TestContentDurationLimitSecondsRoundsUp(t *testing.T) {
	if got := contentDurationLimitSeconds(1500 * time.Millisecond); got != 2 {
		t.Fatalf("seconds=%d", got)
	}
}
