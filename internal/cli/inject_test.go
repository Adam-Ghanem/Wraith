package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestInjectPlanAndDryRunAreAuthorizedNoNetworkCommands(t *testing.T) {
	database := filepath.Join(t.TempDir(), "wraith.db")
	for _, args := range [][]string{
		{"inject", "plan", "https://example.test", "--project", "alpha", "--authorized", "--db", database, "--output", "json"},
		{"inject", "https://example.test", "--project", "alpha", "--authorized", "--db", database, "--dry-run", "--output", "json"},
	} {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), args, &stdout, &stderr); err != nil {
			t.Fatalf("args=%#v err=%v", args, err)
		}
		if !bytes.Contains(stdout.Bytes(), []byte(`"project_id":"alpha"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"estimated_requests":0`)) {
			t.Fatalf("args=%#v output=%s", args, stdout.String())
		}
	}
}
