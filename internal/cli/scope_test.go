package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestScopeCLIRequiresAuthorizationRecordAndValidatesTarget(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/scope.db"
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	var authOutput bytes.Buffer
	if err := Run(ctx, []string{"authorization", "create", "--authorized", "--project", "project-a", "--scope", "scope-v1", "--subject", "example.com", "--type", "assessment", "--evidence", "ticket-1", "--created-by", "operator-a", "--expires", expires, "--db", path, "--json"}, &authOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	id := extractAuthorizationID(t, authOutput.String())
	if err := Run(ctx, []string{"scope", "create", "--authorized", "--project", "project-a", "--version", "scope-v1", "--authorization", id, "--allow", "example.com", "--db", path, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(ctx, []string{"scope", "validate", "--authorized", "--project", "project-a", "--version", "scope-v1", "--authorization", id, "--target", "https://example.com", "--db", path, "--json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"allowed":true`) {
		t.Fatalf("output=%s", output.String())
	}
}
