package evidencecorrelation

import (
	"testing"
	"time"
)

func BenchmarkAnalyzeExactEvidenceChain(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	input := Input{ProjectID: "alpha", Finding: Finding{ID: "finding-1", ProjectID: "alpha", AssetID: "asset-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now}, Validation: Validation{ID: "validation-1", ProjectID: "alpha", Status: "validated", Repeatability: "repeatable", At: now}, Observations: []Observation{{ID: "observation-1", ProjectID: "alpha", SubjectID: "endpoint-1", ObservedAt: now}}, CampaignTasks: []CampaignTask{{ID: "task-1", ProjectID: "alpha", CampaignID: "campaign-1", Status: "completed", ResultReference: "validation-1", FinishedAt: now}}, Freshness: FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Analyze(input); err != nil {
			b.Fatal(err)
		}
	}
}
