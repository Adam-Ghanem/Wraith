package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
