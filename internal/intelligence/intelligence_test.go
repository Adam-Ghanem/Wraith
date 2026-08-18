package intelligence

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestBuildGraphIsProjectIsolatedAndDeduplicatesEdges(t *testing.T) {
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.test/", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := evidence.NewEndpoint("project-a", "GET", "https://example.test/api", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildGraph("project-a", []evidence.WebAsset{asset}, []evidence.Endpoint{endpoint}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Kind != EdgeAssetContainsEndpoint {
		t.Fatalf("graph=%#v", graph)
	}
	foreign, _ := evidence.NewEndpoint("project-b", "GET", "https://example.test/admin", time.Unix(0, 0).UTC())
	if _, err := BuildGraph("project-a", []evidence.WebAsset{asset}, []evidence.Endpoint{foreign}, nil); err == nil {
		t.Fatal("expected cross-project endpoint rejection")
	}
}

func TestBuildGraphDoesNotInventCrossHostContainment(t *testing.T) {
	asset, _ := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.test/", time.Unix(0, 0).UTC())
	endpoint, _ := evidence.NewEndpoint("project-a", "GET", "https://other.example.test/api", time.Unix(0, 0).UTC())
	graph, err := BuildGraph("project-a", []evidence.WebAsset{asset}, []evidence.Endpoint{endpoint}, nil)
	if err != nil || len(graph.Edges) != 0 {
		t.Fatalf("graph=%#v err=%v", graph, err)
	}
}

func TestCorrelateCandidatesUsesEvidenceOnlyAndExplainsConfidence(t *testing.T) {
	candidates := []Candidate{
		{ProjectID: "project-a", RuleID: "security-headers.missing-hsts", SubjectIdentity: "GET https://example.test/", EvidenceIDs: []string{"obs-a", "obs-b"}, ObservedAt: time.Unix(10, 0).UTC()},
		{ProjectID: "project-a", RuleID: "security-headers.missing-hsts", SubjectIdentity: "GET https://example.test/", EvidenceIDs: []string{"obs-b", "obs-c"}, ObservedAt: time.Unix(20, 0).UTC()},
	}
	correlations, err := Correlate("project-a", candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(correlations) != 1 || correlations[0].Lifecycle != LifecycleCorrelated || correlations[0].Confidence.Score <= 0 || len(correlations[0].Confidence.Reasons) == 0 {
		t.Fatalf("correlations=%#v", correlations)
	}
	if correlations[0].ClaimsExploitability {
		t.Fatal("correlation must not claim exploitability")
	}
}
