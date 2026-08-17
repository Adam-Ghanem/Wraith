package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/buildinfo"
)

func TestVersionReportsBuildMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	t.Cleanup(func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.Date = originalVersion, originalCommit, originalDate
	})
	buildinfo.Version = "v0.6.0-test"
	buildinfo.Commit = "abc123"
	buildinfo.Date = "2026-08-17T00:00:00Z"

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"version"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run version: %v", err)
	}
	for _, expected := range []string{"v0.6.0-test", "abc123", "2026-08-17T00:00:00Z"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("version output missing %q: %q", expected, stdout.String())
		}
	}
}
