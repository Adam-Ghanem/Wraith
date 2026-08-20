package regression

import (
	"testing"
	"time"
)

func TestCompareClassifiesDeterministicSecurityRegressions(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 0, 0, 0, 0, time.UTC)
	baseline, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-baseline",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		CreatedAt:     createdAt,
		EndpointIDs:   []string{"endpoint-a"},
		ParameterIDs:  []string{"parameter-a"},
		Findings:      []Finding{{ID: "finding-a", Fingerprint: "finding-fingerprint-a", Severity: "medium", RiskBand: "medium", Status: "accepted"}},
		Evidence:      []Evidence{{FindingID: "finding-a", Verification: "supported", Freshness: "current", Reproducibility: "repeated_consistent"}},
		Coverage:      Coverage{Definition: "recorded_tasks", Numerator: 2, Denominator: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-current",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		CreatedAt:     createdAt.Add(time.Hour),
		EndpointIDs:   []string{"endpoint-a", "endpoint-b"},
		ParameterIDs:  []string{"parameter-a", "parameter-b"},
		Findings:      []Finding{{ID: "finding-a", Fingerprint: "finding-fingerprint-a", Severity: "high", RiskBand: "high", Status: "accepted"}, {ID: "finding-b", Fingerprint: "finding-fingerprint-b", Severity: "high", RiskBand: "high", Status: "accepted"}},
		Evidence:      []Evidence{{FindingID: "finding-a", Verification: "stale", Freshness: "stale", Reproducibility: "cannot_reproduce"}},
		Coverage:      Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Fingerprint == "" || len(comparison.Items) != 7 {
		t.Fatalf("unexpected comparison: %+v", comparison)
	}
	assertChange(t, comparison, CategorySurface, ChangeNewEndpoint, "endpoint-b")
	assertChange(t, comparison, CategorySurface, ChangeNewParameter, "parameter-b")
	assertChange(t, comparison, CategoryFinding, ChangeNewFinding, "finding-fingerprint-b")
	assertChange(t, comparison, CategoryRisk, ChangeRiskIncreased, "finding-fingerprint-a")
	assertChange(t, comparison, CategoryEvidence, ChangeEvidenceStale, "finding-a")
	assertChange(t, comparison, CategoryEvidence, ChangeReproducibilityChanged, "finding-a")
	assertChange(t, comparison, CategoryCoverage, ChangeCoverageDecreased, "recorded_tasks")
}

func TestCompareRejectsCrossProjectSnapshots(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 0, 0, 0, 0, time.UTC)
	baseline, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: createdAt, Coverage: Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewSnapshot(SnapshotInput{ProjectID: "beta", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: createdAt, Coverage: Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(baseline, current); err == nil {
		t.Fatal("expected cross-project comparison rejection")
	}
}

func TestNewSnapshotRejectsSecretBearingSurfaceIdentifier(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: time.Date(2026, time.August, 20, 0, 0, 0, 0, time.UTC), EndpointIDs: []string{"authorization=secret"}, Coverage: Coverage{Definition: "recorded_tasks"}})
	if err == nil {
		t.Fatal("expected secret-bearing endpoint identifier rejection")
	}
}

func TestCompareRejectsForgedSecretBearingSurfaceIdentifier(t *testing.T) {
	baseline, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: time.Date(2026, time.August, 20, 0, 0, 0, 0, time.UTC), EndpointIDs: []string{"endpoint-1"}, Coverage: Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	forged := baseline
	forged.EndpointIDs = []string{"authorization=secret"}
	forged.Fingerprint = snapshotFingerprint(forged)
	if _, err := Compare(baseline, forged); err == nil {
		t.Fatal("expected forged secret-bearing endpoint rejection")
	}
}

func TestCompareDoesNotTreatUnknownCoverageAsZero(t *testing.T) {
	createdAt := time.Date(2026, time.August, 20, 0, 0, 0, 0, time.UTC)
	baseline, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: createdAt, Coverage: Coverage{Definition: "recorded_tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: createdAt.Add(time.Hour), Coverage: Coverage{Definition: "recorded_tasks", Numerator: 1, Denominator: 1}})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range comparison.Items {
		if item.Category == CategoryCoverage {
			t.Fatalf("unknown baseline coverage must not be compared as zero: %+v", item)
		}
	}
}

func assertChange(t *testing.T, comparison Comparison, category Category, change ChangeType, subject string) {
	t.Helper()
	for _, item := range comparison.Items {
		if item.Category == category && item.Change == change && item.Subject == subject {
			return
		}
	}
	t.Fatalf("missing category=%s change=%s subject=%s from %+v", category, change, subject, comparison.Items)
}
