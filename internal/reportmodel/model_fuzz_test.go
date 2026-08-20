package reportmodel

import "testing"

func FuzzNewSnapshotRejectsUnsafeOrMalformedInput(f *testing.F) {
	f.Add("alpha", "campaign-1", "scope-v1", "finding-1")
	f.Add("token=opaque", "campaign-1", "scope-v1", "finding-1")
	f.Add("alpha", "campaign-1", "scope-v1", "password=value")
	f.Fuzz(func(t *testing.T, projectID, campaignID, scopeVersion, findingID string) {
		_, _ = NewSnapshot(SnapshotInput{ProjectID: projectID, CampaignID: campaignID, ScopeVersion: scopeVersion, SchemaVersion: SchemaVersion, Findings: []Finding{{ID: findingID, RiskScore: 50}}, Coverage: CoverageMetric{Definition: "tasks", Numerator: 0, Denominator: 0}})
	})
}
