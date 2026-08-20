package correlation

import "testing"

func TestCorrelateFindingUsesExactProjectScopedReferences(t *testing.T) {
	result := CorrelateFinding(FindingInput{ProjectID: "alpha", FindingID: "finding-1", EndpointID: "endpoint-1", EvidenceReferences: []string{"observation-1"}}, Inventory{ProjectID: "alpha", Endpoints: map[string]struct{}{"endpoint-1": {}}, Observations: map[string]struct{}{"observation-1": {}}})
	if result.Uncorrelated || result.EndpointID != "endpoint-1" || len(result.EvidenceReferences) != 1 {
		t.Fatalf("result=%+v", result)
	}
	foreign := CorrelateFinding(FindingInput{ProjectID: "alpha", FindingID: "finding-2", EndpointID: "endpoint-1"}, Inventory{ProjectID: "beta", Endpoints: map[string]struct{}{"endpoint-1": {}}})
	if !foreign.Uncorrelated {
		t.Fatalf("cross-project input correlated: %+v", foreign)
	}
}
