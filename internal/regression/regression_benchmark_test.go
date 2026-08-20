package regression

import (
	"testing"
	"time"
)

func BenchmarkCompareRecordedAssessmentStates(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	baseline, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: now, EndpointIDs: []string{"endpoint-1", "endpoint-2"}, ParameterIDs: []string{"parameter-1"}, Findings: []Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "medium", RiskBand: "medium", Status: "open"}}, Evidence: []Evidence{{FindingID: "finding-1", Verification: "supported", Freshness: "current", Reproducibility: "repeatable"}}, Coverage: Coverage{Definition: "recorded_tasks", Numerator: 8, Denominator: 10}})
	if err != nil {
		b.Fatal(err)
	}
	current, err := NewSnapshot(SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-2", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: now.Add(time.Hour), EndpointIDs: []string{"endpoint-1", "endpoint-2", "endpoint-3"}, ParameterIDs: []string{"parameter-1", "parameter-2"}, Findings: []Finding{{ID: "finding-1", Fingerprint: "finding-fingerprint-1", Severity: "high", RiskBand: "high", Status: "open"}, {ID: "finding-2", Fingerprint: "finding-fingerprint-2", Severity: "medium", RiskBand: "medium", Status: "open"}}, Evidence: []Evidence{{FindingID: "finding-1", Verification: "supported", Freshness: "stale", Reproducibility: "single_observation"}}, Coverage: Coverage{Definition: "recorded_tasks", Numerator: 7, Denominator: 10}})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Compare(baseline, current); err != nil {
			b.Fatal(err)
		}
	}
}
