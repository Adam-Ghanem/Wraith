package attacksurface

import (
	"testing"
	"time"
)

func TestBuildGraphIsDeterministicEvidenceBackedAndProjectScoped(t *testing.T) {
	input := GraphInput{ProjectID: "alpha", Assets: []Asset{{ID: "asset:url:https://app.test", ProjectID: "alpha"}}, Endpoints: []Endpoint{{ID: "GET https://app.test/api/items", ProjectID: "alpha", AssetID: "asset:url:https://app.test", Classes: []string{"api"}}}, Parameters: []Parameter{{ID: "GET https://app.test/api/items|query|page", ProjectID: "alpha", EndpointID: "GET https://app.test/api/items"}}, Findings: []Finding{{ID: "finding-1", ProjectID: "alpha", EndpointID: "GET https://app.test/api/items", ParameterID: "GET https://app.test/api/items|query|page", AssetID: "asset:url:https://app.test", RiskScore: 70, Status: "open", EvidenceIDs: []string{"obs-1"}}}}
	first, err := BuildGraph(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildGraph(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || len(first.Nodes) != 8 || len(first.Edges) < 5 {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	for _, edge := range first.Edges {
		if edge.ProjectID != "alpha" || edge.ID == "" {
			t.Fatalf("edge=%#v", edge)
		}
	}
	cross := input
	cross.Endpoints = append(cross.Endpoints, Endpoint{ID: "GET https://other.test/", ProjectID: "beta", AssetID: "asset:url:https://other.test"})
	if _, err := BuildGraph(cross); err == nil {
		t.Fatal("expected cross-project graph rejection")
	}
}

func TestSnapshotDiffCoverageAndVisibilityGapsAreBounded(t *testing.T) {
	base, err := BuildGraph(GraphInput{ProjectID: "alpha", Assets: []Asset{{ID: "asset-1", ProjectID: "alpha"}}, Endpoints: []Endpoint{{ID: "endpoint-1", ProjectID: "alpha", AssetID: "asset-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := BuildGraph(GraphInput{ProjectID: "alpha", Assets: []Asset{{ID: "asset-1", ProjectID: "alpha"}}, Endpoints: []Endpoint{{ID: "endpoint-1", ProjectID: "alpha", AssetID: "asset-1"}}, Parameters: []Parameter{{ID: "parameter-1", ProjectID: "alpha", EndpointID: "endpoint-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	previous := NewSnapshot(base, "r11.5-v1", time.Unix(1, 0))
	now := NewSnapshot(current, "r11.5-v1", time.Unix(2, 0))
	diff, err := DiffSnapshots(previous, now)
	if err != nil || len(diff.Added) == 0 || len(diff.Removed) != 0 {
		t.Fatalf("diff=%#v err=%v", diff, err)
	}
	coverage := CalculateCoverage(base)
	if coverage.EndpointDiscovery != 100 || coverage.ParameterDiscovery != 0 || len(VisibilityGaps(base)) == 0 {
		t.Fatalf("coverage=%#v gaps=%#v", coverage, VisibilityGaps(base))
	}
}
