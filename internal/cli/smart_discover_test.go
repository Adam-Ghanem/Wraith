package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestSmartDiscoverDryRunUsesPositionalTargetAndProducesNoNetworkPlan(t *testing.T) {
	database := filepath.Join(t.TempDir(), "wraith.db")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"discover", "https://example.test", "--project", "alpha", "--authorized", "--db", database, "--dry-run", "--output", "json"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"project_id":"alpha"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"estimated_requests":0`)) {
		t.Fatalf("unexpected dry-run output=%s", stdout.String())
	}
}
