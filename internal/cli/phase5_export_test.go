package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExportFixturesRemainBlockedByT6BeforeRunners(t *testing.T) {
	originalScanRunner, originalHistoryRunner := fixtureScanRunner, fixtureHistoryRunner
	t.Cleanup(func() {
		fixtureScanRunner = originalScanRunner
		fixtureHistoryRunner = originalHistoryRunner
	})
	called := false
	fixtureScanRunner = func(_ context.Context, _ []string, _ io.Writer, _ io.Writer) error {
		called = true
		return nil
	}
	err := Run(context.Background(), []string{"export-fixtures", "-d", "example.com", "--out", t.TempDir(), "--authorized"}, io.Discard, io.Discard)
	if !errors.Is(err, ErrProviderOutboundBlocked) || called {
		t.Fatalf("err=%v runner_called=%t", err, called)
	}
}

func TestExportFixturesBlockBeforeWritingOutput(t *testing.T) {
	outDir := t.TempDir()
	err := Run(context.Background(), []string{"export-fixtures", "-d", "example.com", "--db", filepath.Join(t.TempDir(), "wraith.db"), "--out", outDir, "--authorized"}, io.Discard, io.Discard)
	if !errors.Is(err, ErrProviderOutboundBlocked) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "scan.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("scan.json must not be created: %v", statErr)
	}
}
