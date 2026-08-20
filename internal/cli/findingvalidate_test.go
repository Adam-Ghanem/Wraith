package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestFindingValidationPlanIsExplicitAndNoNetwork(t *testing.T) {
	options, err := parseFindingValidationOptions([]string{"validate", "plan", "https://example.test", "--project", "alpha", "--authorized", "--signal", "signal-1", "--profile", "standard", "--output", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if options.ExpectedRequests != 4 || options.Profile != "standard" {
		t.Fatalf("options=%#v", options)
	}
	var stdout bytes.Buffer
	if err := runFindingValidationPlan(context.Background(), []string{"validate", "plan", "https://example.test", "--project", "alpha", "--authorized", "--signal", "signal-1", "--profile", "standard", "--output", "json"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"estimated_requests":4`) || !strings.Contains(stdout.String(), `"active_execution":"not started by CLI"`) {
		t.Fatalf("output=%s", stdout.String())
	}
}
