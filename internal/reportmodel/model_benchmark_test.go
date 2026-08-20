package reportmodel

import "testing"

func BenchmarkNewSnapshot(b *testing.B) {
	input := SnapshotInput{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, Findings: []Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}, {ID: "finding-2", Severity: "medium", RiskScore: 50}}, Limitations: []string{"recorded data only"}, Coverage: CoverageMetric{Definition: "tasks", Numerator: 1, Denominator: 2}}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := NewSnapshot(input); err != nil {
			b.Fatal(err)
		}
	}
}
