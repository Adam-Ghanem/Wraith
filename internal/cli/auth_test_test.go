package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAuthTestOptionsRequiresDualGate(t *testing.T) {
	base := []string{"auth-test", "--project", "project-a", "--authorized", "--target", "https://example.test/login", "--mode", "bruteforce", "--max-attempts", "1", "--max-attempts-per-identity", "1", "--rate", "1", "--concurrency", "1", "--max-duration", "1s"}
	if _, err := parseAuthTestOptions(base); err == nil {
		t.Fatal("expected attack-auth gate")
	}
	options, err := parseAuthTestOptions(append(base, "--attack-auth", "--dry-run"))
	if err != nil || !options.DryRun || !options.AttackAuth {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}

func TestRunAuthTestDryRunDoesNotReadCredentialSource(t *testing.T) {
	missingSource := filepath.Join(t.TempDir(), "absent.txt")
	args := []string{"auth-test", "--project", "project-a", "--authorized", "--attack-auth", "--target", "https://example.test/login", "--mode", "bruteforce", "--max-attempts", "1", "--max-attempts-per-identity", "1", "--rate", "1", "--concurrency", "1", "--max-duration", "1s", "--credentials", missingSource, "--dry-run"}
	var output strings.Builder
	if err := runAuthTest(context.Background(), args, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "dry_run") || strings.Contains(output.String(), missingSource) {
		t.Fatalf("unexpected dry-run output %q", output.String())
	}
}
