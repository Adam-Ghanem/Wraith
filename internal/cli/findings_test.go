package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestFindingsAndRiskCommandsAreProjectScopedAndLocal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "risk.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	finding := storage.SecurityFindingRecord{FindingID: "finding-1", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", CorrelationID: "correlation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", Class: "sql", Subtype: "validated_sql", Title: "Validated behavior", Description: "Bounded evidence", RemediationHint: "Use parameterized queries.", Confidence: "high", Severity: "high", RiskScore: 70, RiskBand: "high", RiskModelVersion: "r11.5-v1", RiskFactorsJSON: `[]`, RiskReason: "deterministic", Status: "open", FirstSeenAt: time.Unix(1, 0), LastSeenAt: time.Unix(1, 0), ValidatedAt: time.Unix(1, 0), RiskCalculatedAt: time.Unix(1, 0), Fingerprint: "fingerprint-1", EvidenceReferences: []string{"observation-1"}}
	if err := database.UpsertSecurityFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var findings, summary bytes.Buffer
	if err := runFindings(ctx, []string{"findings", "--project", "alpha", "--db", path, "--output", "json"}, &findings, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runRisk(ctx, []string{"risk", "--project", "alpha", "--db", path, "--output", "json"}, &summary, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(findings.String(), `"finding_id":"finding-1"`) || strings.Contains(findings.String(), "fingerprint-1") || !strings.Contains(summary.String(), `"high":1`) {
		t.Fatalf("findings=%s summary=%s", findings.String(), summary.String())
	}
}
