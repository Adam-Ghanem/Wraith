package cli

import "testing"

func TestParseValidateOptionsRequiresAuthorizationAndEndpoint(t *testing.T) {
	if _, err := parseValidateOptions([]string{"validate", "--project", "project-a"}); err == nil {
		t.Fatal("expected required options")
	}
	o, err := parseValidateOptions([]string{"validate", "--project", "project-a", "--authorized", "--endpoint", "GET https://example.test/", "--max-requests", "1", "--max-duration", "15s", "--concurrency", "1", "--rate", "1", "--dry-run"})
	if err != nil || !o.DryRun || o.ProjectID != "project-a" {
		t.Fatalf("options=%#v err=%v", o, err)
	}
}
