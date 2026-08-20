package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationCLIRequiresAttestationAndValidatesProjectScopedRecord(t *testing.T) {
	ctx := context.Background()
	databasePath := t.TempDir() + "/authorizations.db"
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	base := []string{"authorization", "create", "--project", "project-a", "--scope", "scope-v1", "--subject", "example.com", "--type", "assessment", "--evidence", "ticket-123", "--created-by", "operator-a", "--expires", expires, "--db", databasePath, "--json"}
	if err := Run(ctx, base, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("authorization create without --authorized was accepted")
	}
	var output bytes.Buffer
	args := append([]string{"authorization", "create", "--authorized"}, base[2:]...)
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"active"`) {
		t.Fatalf("output=%s", output.String())
	}
	if err := Run(ctx, []string{"authorization", "validate", "--authorized", "--project", "project-b", "--scope", "scope-v1", "--id", extractAuthorizationID(t, output.String()), "--db", databasePath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("cross-project authorization validation was accepted")
	}
	if err := Run(ctx, []string{"authorization", "validate", "--authorized", "--project", "project-a", "--scope", "scope-v1", "--id", extractAuthorizationID(t, output.String()), "--db", databasePath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func extractAuthorizationID(t *testing.T, output string) string {
	t.Helper()
	marker := `"authorization_id":"`
	start := strings.Index(output, marker)
	if start < 0 {
		t.Fatalf("missing id in %s", output)
	}
	value := output[start+len(marker):]
	end := strings.Index(value, `"`)
	if end < 0 {
		t.Fatalf("malformed id in %s", output)
	}
	return value[:end]
}
