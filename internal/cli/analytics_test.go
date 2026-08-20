package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAnalyticsSummaryRendersDeterministicJSONAndRejectsReversedWindow(t *testing.T) {
	ctx := context.Background()
	path, _ := governCLIFixture(t, ctx)
	var stdout, stderr bytes.Buffer
	if err := Run(ctx, []string{"analytics", "summary", "--project", "alpha", "--db", path, "--from", "2026-08-20T10:00:00Z", "--to", "2026-08-20T12:30:00Z", "--format", "json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"schema_version":"r21.v1"`) || !strings.Contains(stdout.String(), `"project":"alpha"`) || !strings.Contains(stdout.String(), `"policy_failure_count":1`) {
		t.Fatalf("analytics JSON=%s", stdout.String())
	}
	if err := Run(ctx, []string{"analytics", "summary", "--project", "alpha", "--db", path, "--from", "2026-08-21T12:00:00Z", "--to", "2026-08-20T12:00:00Z"}, &stdout, &stderr); !errors.Is(err, ErrAnalyticsInvalidInput) || ExitCode(err) != 2 {
		t.Fatalf("expected invalid analytics range exit 2, err=%v code=%d", err, ExitCode(err))
	}
}
