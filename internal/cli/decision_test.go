package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunDecisionRequiresExistingAuthorizedGate(t *testing.T) {
	var stdout strings.Builder
	err := runDecision(context.Background(), []string{"decision", "evaluate", "--project", "alpha", "--db", "decision.db", "--dry-run"}, &stdout)
	if !errors.Is(err, ErrDecisionInvalidInput) {
		t.Fatalf("runDecision() error = %v, want ErrDecisionInvalidInput", err)
	}
}

func TestRunDecisionRejectsUnsafeExportPathBeforeDatabaseAccess(t *testing.T) {
	var stdout strings.Builder
	err := runDecision(context.Background(), []string{"decision", "export", "--project", "alpha", "--authorized", "--id", strings.Repeat("a", 64), "--output", "../escape.json", "--db", "decision.db"}, &stdout)
	if !errors.Is(err, ErrDecisionInvalidInput) {
		t.Fatalf("runDecision() error = %v, want ErrDecisionInvalidInput", err)
	}
}
