package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunIdentityCreatesAndListsProjectScopedIdentity(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wraith.sqlite")
	var out strings.Builder
	if err := runIdentity(context.Background(), []string{"identity", "create", "--project", "demo", "--name", "reader", "--role", "user", "--db", dbPath}, &out, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runIdentity(context.Background(), []string{"identity", "list", "--project", "demo", "--db", dbPath, "--json"}, &out, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "reader") || strings.Contains(out.String(), "password") {
		t.Fatalf("unexpected identity output %q", out.String())
	}
}
