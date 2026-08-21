package attacksurface

import (
	"testing"
	"time"
)

func TestBuildCampaignPlanIsDeterministicBoundedAndProjectScoped(t *testing.T) {
	graph, err := BuildGraph(GraphInput{ProjectID: "alpha", Assets: []Asset{{ID: "asset-1", ProjectID: "alpha"}}, Endpoints: []Endpoint{{ID: "endpoint-1", ProjectID: "alpha", AssetID: "asset-1"}}, Findings: []Finding{{ID: "finding-high", ProjectID: "alpha", EndpointID: "endpoint-1", AssetID: "asset-1", RiskScore: 90, Status: "open", EvidenceIDs: []string{"obs-1"}}, {ID: "finding-low", ProjectID: "alpha", EndpointID: "endpoint-1", AssetID: "asset-1", RiskScore: 30, Status: "open", EvidenceIDs: []string{"obs-2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := NewSnapshot(graph, "r11.5-v1", time.Unix(1, 0))
	first, err := BuildCampaignPlan(CampaignInput{ProjectID: "alpha", Name: "Review", Graph: graph, Snapshot: snapshot, Budget: CampaignBudget{MaxTasks: 1, MaxValidationRequests: 1, MaxDuration: time.Minute, MaxConcurrency: 1}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCampaignPlan(CampaignInput{ProjectID: "alpha", Name: "Review", Graph: graph, Snapshot: snapshot, Budget: CampaignBudget{MaxTasks: 1, MaxValidationRequests: 1, MaxDuration: time.Minute, MaxConcurrency: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if first.CampaignID != second.CampaignID || len(first.Tasks) != 1 || first.Tasks[0].ReferenceID != "finding-high" || first.Status != CampaignPlanned {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	bad := graph
	bad.ProjectID = "beta"
	if _, err := BuildCampaignPlan(CampaignInput{ProjectID: "alpha", Name: "Review", Graph: bad, Snapshot: snapshot, Budget: CampaignBudget{MaxTasks: 1, MaxValidationRequests: 1, MaxDuration: time.Minute, MaxConcurrency: 1}}); err == nil {
		t.Fatal("expected cross-project campaign rejection")
	}
}
