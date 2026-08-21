package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

func TestGovernancePolicyCreateRequiresExistingT1AuthorizationAndListsWithinProject(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/governance-cli.db"
	database, err := openAssessmentDB(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "owner", Type: authorization.TypeAssessment, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAuthorizationRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err = runGovernance(ctx, []string{"governance", "policy", "create", "--project", "project-a", "--scope", "scope-v1", "--authorization-id", record.AuthorizationID, "--version", "governance-v1", "--rule", "local_storage:sensitive:720h", "--db", dbPath}, &stdout)
	if err == nil || !strings.Contains(err.Error(), "--authorized") {
		t.Fatalf("missing acknowledgement error=%v", err)
	}
	stdout.Reset()
	err = runGovernance(ctx, []string{"governance", "policy", "create", "--project", "project-a", "--scope", "scope-v1", "--authorization-id", record.AuthorizationID, "--authorized", "--version", "governance-v1", "--rule", "local_storage:sensitive:720h", "--rule", "audit_log:internal:720h", "--db", dbPath}, &stdout)
	if err != nil || !strings.Contains(stdout.String(), "governance-v1") {
		t.Fatalf("policy create stdout=%q err=%v", stdout.String(), err)
	}
	stdout.Reset()
	err = runGovernance(ctx, []string{"governance", "policy", "show", "--project", "project-a", "--version", "governance-v1", "--db", dbPath}, &stdout)
	if err != nil || !strings.Contains(stdout.String(), "fingerprint=") || !strings.Contains(stdout.String(), "governance-v1") {
		t.Fatalf("policy show stdout=%q err=%v", stdout.String(), err)
	}
	stdout.Reset()
	err = runGovernance(ctx, []string{"governance", "policy", "list", "--project", "project-a", "--db", dbPath}, &stdout)
	if err != nil || !strings.Contains(stdout.String(), "governance-v1") {
		t.Fatalf("policy list stdout=%q err=%v", stdout.String(), err)
	}
}

func TestGovernanceRetentionPurgeOnlyPermitsDryRun(t *testing.T) {
	var stdout bytes.Buffer
	err := runGovernance(context.Background(), []string{"governance", "retention", "purge", "--project", "project-a", "--authorized"}, &stdout)
	if err == nil || !strings.Contains(err.Error(), "dry-run") {
		t.Fatalf("non-dry-run purge error=%v", err)
	}
}
