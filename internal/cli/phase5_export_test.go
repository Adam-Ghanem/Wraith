package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestExportFixturesWritesCanonicalScanAndHistoryJSON(t *testing.T) {
	originalScanRunner, originalHistoryRunner := fixtureScanRunner, fixtureHistoryRunner
	t.Cleanup(func() {
		fixtureScanRunner = originalScanRunner
		fixtureHistoryRunner = originalHistoryRunner
	})
	fixtureScanRunner = func(_ context.Context, args []string, stdout, _ io.Writer) error {
		if got := strings.Join(args, " "); !strings.Contains(got, "scan -d example.com --authorized --json --db ") {
			t.Fatalf("unexpected scan args: %q", got)
		}
		return renderScanOutput(stdout, true, scanOutput{
			ScanID:       2,
			Target:       "example.com",
			Subdomains:   []storage.SubdomainRecord{{ID: 7, ScanID: 2, Domain: "example.com", Subdomain: "app.example.com", StatusCode: 200, FirstSeen: "2026-08-17T10:00:00Z", LastSeen: "2026-08-17T10:00:01Z"}},
			SourceErrors: []string{"crt: temporary failure"},
		})
	}
	fixtureHistoryRunner = func(_ context.Context, args []string, stdout, _ io.Writer) error {
		if got := strings.Join(args, " "); !strings.Contains(got, "history -d example.com --authorized --json --db ") {
			t.Fatalf("unexpected history args: %q", got)
		}
		return renderHistoryOutput(stdout, true, historyOutput{
			Target:       "example.com",
			PreviousScan: storage.ScanRecord{ID: 1},
			CurrentScan:  storage.ScanRecord{ID: 2},
			Changes:      []storage.SubdomainChange{{Kind: storage.ChangeChanged, Subdomain: "app.example.com", Previous: &storage.SubdomainSnapshot{StatusCode: 301}, Current: &storage.SubdomainSnapshot{StatusCode: 200}}},
		})
	}

	outDir := t.TempDir()
	var stderr bytes.Buffer
	if err := Run(context.Background(), []string{"export-fixtures", "-d", "example.com", "--db", filepath.Join(t.TempDir(), "wraith.db"), "--out", outDir, "--authorized"}, io.Discard, &stderr); err != nil {
		t.Fatalf("export fixtures: %v", err)
	}

	for _, fileName := range []string{"scan.json", "history.json"} {
		contents, err := os.ReadFile(filepath.Join(outDir, fileName))
		if err != nil {
			t.Fatalf("read %s: %v", fileName, err)
		}
		if !json.Valid(contents) {
			t.Fatalf("%s is not valid JSON: %s", fileName, contents)
		}
	}
	var scan scanOutput
	contents, err := os.ReadFile(filepath.Join(outDir, "scan.json"))
	if err != nil {
		t.Fatalf("read scan fixture: %v", err)
	}
	if err := json.Unmarshal(contents, &scan); err != nil {
		t.Fatalf("decode scan fixture: %v", err)
	}
	if scan.ScanID != 2 || len(scan.Subdomains) != 1 || scan.Subdomains[0].ID != 7 || len(scan.SourceErrors) != 1 {
		t.Fatalf("scan fixture does not preserve canonical data: %+v", scan)
	}
}

func TestExportFixturesWritesScanAndFailsClosedWithoutHistory(t *testing.T) {
	originalScanRunner, originalHistoryRunner := fixtureScanRunner, fixtureHistoryRunner
	t.Cleanup(func() {
		fixtureScanRunner = originalScanRunner
		fixtureHistoryRunner = originalHistoryRunner
	})
	fixtureScanRunner = func(_ context.Context, _ []string, stdout, _ io.Writer) error {
		return renderScanOutput(stdout, true, scanOutput{ScanID: 1, Target: "example.com"})
	}
	fixtureHistoryRunner = func(_ context.Context, _ []string, _ io.Writer, _ io.Writer) error {
		return errors.New("history requires two completed scans for the authorized domain")
	}

	outDir := t.TempDir()
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"export-fixtures", "-d", "example.com", "--db", filepath.Join(t.TempDir(), "wraith.db"), "--out", outDir, "--authorized"}, io.Discard, &stderr)
	if err == nil || !strings.Contains(err.Error(), "history requires two completed scans") {
		t.Fatalf("expected history failure, got %v", err)
	}
	if _, readErr := os.Stat(filepath.Join(outDir, "scan.json")); readErr != nil {
		t.Fatalf("scan.json should still be written: %v", readErr)
	}
	if _, readErr := os.Stat(filepath.Join(outDir, "history.json")); !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("history.json must not be retained after a failed history export: %v", readErr)
	}
	if !strings.Contains(stderr.String(), "scan.json was written") {
		t.Fatalf("expected stderr note that scan.json was written: %q", stderr.String())
	}
}

func TestExportFixturesRequiresAuthorization(t *testing.T) {
	err := Run(context.Background(), []string{"export-fixtures", "-d", "example.com", "--out", t.TempDir()}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "requires explicit authorization") {
		t.Fatalf("expected explicit authorization error, got %v", err)
	}
}
