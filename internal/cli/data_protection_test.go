package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

func TestDataProtectRequiresT1AuthorizationAndT7Policy(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/data-protection-cli.db"
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
	policy, err := datagovernance.NewPolicy(datagovernance.PolicyInput{ProjectID: "project-a", Version: "governance-v1", CreatedAt: now, Rules: []datagovernance.Rule{{Consumer: datagovernance.ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveDataGovernancePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	args := []string{"data", "protect", "--project", "project-a", "--scope", "scope-v1", "--authorization-id", record.AuthorizationID, "--policy-version", "governance-v1", "--object", "evidence", "--object-id", "evidence-1", "--classification", "internal", "--source", "observation-1", "--profile", "technical-output", "--db", dbPath}
	var stdout bytes.Buffer
	if err := runData(ctx, args, &stdout); err == nil || !strings.Contains(err.Error(), "--authorized") {
		t.Fatalf("missing acknowledgement error=%v", err)
	}
	stdout.Reset()
	args = append(args, "--authorized")
	if err := runData(ctx, args, &stdout); err != nil || !strings.Contains(stdout.String(), "action=allow") || !strings.Contains(stdout.String(), "fingerprint=") {
		t.Fatalf("protect stdout=%q err=%v", stdout.String(), err)
	}
}

func TestDataRedactNeverEchoesSecretLikeValue(t *testing.T) {
	var stdout bytes.Buffer
	err := runData(context.Background(), []string{"data", "redact", "--value", "Authorization: Bearer example-token"}, &stdout)
	if err != nil || strings.Contains(stdout.String(), "example-token") || !strings.Contains(stdout.String(), dataclassification.RedactedValue) {
		t.Fatalf("redact stdout=%q err=%v", stdout.String(), err)
	}
}
