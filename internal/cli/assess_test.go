package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestAssessAppliesPolicyCreatesBaselineAndFailsCheckOffline(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r19-cli.db")
	database, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 20, 11, 0, 0, 0, time.UTC)
	baseline, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-baseline", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := regression.NewSnapshot(regression.SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-current", ScopeVersion: "scope-v1", SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt.Add(time.Hour), EndpointIDs: []string{"endpoint-1"}, Coverage: regression.Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []regression.Snapshot{baseline, current} {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.SaveRegressionSnapshot(ctx, storage.RegressionSnapshotRecord{ProjectID: "alpha", SnapshotID: snapshot.Fingerprint, CampaignID: snapshot.CampaignID, ScopeVersion: snapshot.ScopeVersion, SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
			t.Fatal(err)
		}
	}
	comparison, err := regression.Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	comparisonJSON, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveRegressionComparison(ctx, storage.RegressionComparisonRecord{ProjectID: "alpha", BaselineSnapshotID: baseline.Fingerprint, CurrentSnapshotID: current.Fingerprint, Fingerprint: comparison.Fingerprint, ComparisonJSON: string(comparisonJSON), CreatedAt: current.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	policyDocument := []byte(`{"project_id":"alpha","name":"production-security","version":1,"rules":[{"id":"no-regressions","type":"regression","operator":"maximum","threshold":{"value":0,"unit":"count"},"effect":"fail"}]}`)
	policy, err := continuousassessment.ParsePolicy(policyDocument)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, policyDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"assess", "policy", "apply", "--project", "alpha", "--file", policyPath, "--as-of", createdAt.Format(time.RFC3339), "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	baselineRecord, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: "alpha", SnapshotFingerprint: baseline.Fingerprint, SnapshotCreatedAt: baseline.CreatedAt, PolicyFingerprint: policy.Fingerprint, CampaignID: baseline.CampaignID, CreatedAt: baseline.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, []string{"assess", "baseline", "create", "--project", "alpha", "--snapshot", baseline.Fingerprint, "--policy", policy.Fingerprint, "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var technical bytes.Buffer
	if err := Run(ctx, []string{"assess", "evaluate", "--project", "alpha", "--baseline", baselineRecord.Fingerprint, "--snapshot", current.Fingerprint, "--policy", policy.Fingerprint, "--db", path, "--format", "markdown"}, &technical, &bytes.Buffer{}); err != nil || !strings.Contains(technical.String(), "# Wraith Assessment Report") || !strings.Contains(technical.String(), "## Continuous Assessment Control") {
		t.Fatalf("output=%s err=%v", technical.String(), err)
	}
	err = Run(ctx, []string{"assess", "check", "--project", "alpha", "--baseline", baselineRecord.Fingerprint, "--snapshot", current.Fingerprint, "--policy", policy.Fingerprint, "--db", path, "--format", "json"}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrAssessmentPolicyFailed) {
		t.Fatalf("expected deterministic policy failure, got %v", err)
	}
	if err := Run(ctx, []string{"assess", "baseline", "create", "--project", "beta", "--snapshot", baseline.Fingerprint, "--policy", policy.Fingerprint, "--db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected cross-project snapshot rejection")
	}
}

func TestAssessmentExitCodeClassifiesCIFailuresDeterministically(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(ErrAssessmentPolicyFailed) != 1 || ExitCode(ErrAssessmentInvalidInput) != 2 || ExitCode(errors.New("legacy invalid command")) != 2 || ExitCode(fmt.Errorf("%w: storage unavailable", ErrAssessmentInternal)) != 3 {
		t.Fatalf("unexpected exit-code mapping")
	}
}

func TestAssessRejectsTraversalPathsAndOversizedPolicyDocuments(t *testing.T) {
	ctx := context.Background()
	if err := Run(ctx, []string{"assess", "policy", "validate", "--project", "alpha", "--file", "../policy.json"}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrAssessmentInvalidInput) {
		t.Fatalf("expected policy traversal rejection, got %v", err)
	}
	if err := Run(ctx, []string{"assess", "evaluate", "--project", "alpha", "--baseline", "baseline", "--snapshot", "snapshot", "--policy", "policy", "--output", "../report.json"}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrAssessmentInvalidInput) {
		t.Fatalf("expected output traversal rejection, got %v", err)
	}
	if _, err := continuousassessment.ParsePolicy(bytes.Repeat([]byte("a"), continuousassessment.MaxPolicyBytes+1)); err == nil {
		t.Fatal("expected oversized policy rejection")
	}
}
