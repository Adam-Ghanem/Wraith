package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRoutesHistoryAwayFromDiscoverUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"history", "-d", "example.com", "--authorized", "--db", t.TempDir() + "/history.db"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected empty history to return a useful error")
	}
	if strings.Contains(err.Error(), "usage: wraith discover") {
		t.Fatalf("history incorrectly used discover parser: %v", err)
	}
}
