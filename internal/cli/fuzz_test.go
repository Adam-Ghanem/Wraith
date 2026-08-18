package cli

import "testing"

func TestParseFuzzOptionsRequiresExplicitAuthorizedTargetSelection(t *testing.T) {
	valid := []string{"fuzz", "--project", "project-a", "--authorized", "--endpoint", "GET https://example.test/api/users", "--parameter", "id", "--location", "query", "--profile", "minimal", "--dry-run"}
	options, err := parseFuzzOptions(valid)
	if err != nil || !options.Authorized || !options.DryRun || options.EndpointIdentity != "GET https://example.test/api/users" || options.Parameter != "id" || options.Location != "query" || options.Profile != "minimal" {
		t.Fatalf("options=%#v err=%v", options, err)
	}
	for _, args := range [][]string{{"fuzz", "--project", "project-a", "--authorized"}, {"fuzz", "--project", "project-a", "--endpoint", "GET https://example.test/api/users", "--parameter", "id", "--location", "query", "--profile", "minimal"}, {"fuzz", "--project", "project-a", "--authorized", "--endpoint", "GET https://example.test/api/users", "--parameter", "id", "--location", "query", "--profile", "unknown"}} {
		if _, err := parseFuzzOptions(args); err == nil {
			t.Fatalf("expected invalid options for %v", args)
		}
	}
}
