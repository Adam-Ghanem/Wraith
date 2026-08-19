package reportmodel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSnapshotNormalizesOrderAndUsesStableContentFingerprint(t *testing.T) {
	first, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Findings:      []Finding{{ID: "finding-b", Severity: "high", RiskScore: 70}, {ID: "finding-a", Severity: "medium", RiskScore: 50}},
		Limitations:   []string{"surface membership unavailable", "owner unavailable"},
		Coverage:      CoverageMetric{Definition: "executed tasks divided by planned tasks", Numerator: 0, Denominator: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot(SnapshotInput{
		ProjectID:     "alpha",
		CampaignID:    "campaign-1",
		ScopeVersion:  "scope-v1",
		SchemaVersion: SchemaVersion,
		Findings:      []Finding{{ID: "finding-a", Severity: "medium", RiskScore: 50}, {ID: "finding-b", Severity: "high", RiskScore: 70}},
		Limitations:   []string{"owner unavailable", "surface membership unavailable"},
		Coverage:      CoverageMetric{Definition: "executed tasks divided by planned tasks", Numerator: 0, Denominator: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints differ: %q != %q", first.Fingerprint, second.Fingerprint)
	}
	if got := first.Coverage.Display(); got != "N/A" {
		t.Fatalf("zero denominator coverage = %q, want N/A", got)
	}
	if first.Findings[0].ID != "finding-a" || first.Limitations[0] != "owner unavailable" {
		t.Fatalf("snapshot was not normalized: %+v", first)
	}
}

func TestSnapshotRejectsSecretLikeFindingIdentity(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Findings: []Finding{{ID: "token=opaque", Severity: "high", RiskScore: 70}}, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like finding identity was accepted")
	}
}

func TestSnapshotRejectsSecretLikeContextIdentity(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-token=opaque", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like campaign identity was accepted")
	}
}

func TestSnapshotRejectsSecretLikeTarget(t *testing.T) {
	_, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", Target: "https://app.test/?token=opaque", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err == nil {
		t.Fatal("secret-like target was accepted")
	}
}

func TestSnapshotNormalizesEmptyCollectionsToJSONArrays(t *testing.T) {
	snapshot, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), `"findings":null`) || strings.Contains(string(encoded), `"limitations":null`) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}
