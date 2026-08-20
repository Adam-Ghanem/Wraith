package smartdiscovery

import (
	"reflect"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/jsanalysis"
)

func TestBuildCandidatesUsesR5InventoryAndMergesIndependentProvenance(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/api/v1/users", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "page", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	inventory := endpointintelligence.Inventory{ProjectID: "alpha", Endpoints: []endpointintelligence.Endpoint{{Identity: endpoint.Identity, Method: endpoint.Method, URL: endpoint.URL, Parameters: []endpointintelligence.Parameter{{Identity: parameter.Identity, Name: parameter.Name, Location: parameter.Location}}}}}
	input := Input{ProjectID: "alpha", BaseURL: "https://example.test", Inventory: inventory, Seeds: []Seed{{Type: CandidatePath, Value: "/api/v1/users", Source: SourceJavaScript, EvidenceID: "js:bundle"}, {Type: CandidatePath, Value: "/api/v1/users/", Source: SourceCrawler, EvidenceID: "crawl:page"}}, Heuristics: true, Limits: DefaultLimits()}
	first, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic output first=%#v second=%#v", first, second)
	}
	path := findCandidate(t, first.Candidates, CandidatePath, "https://example.test/api/v1/users")
	if len(path.Provenance) != 2 || path.Priority != PriorityHigh || path.Confidence != ConfidenceHigh {
		t.Fatalf("merged candidate=%#v", path)
	}
	if findCandidate(t, first.Candidates, CandidateEndpoint, endpoint.URL).EndpointIdentity != endpoint.Identity {
		t.Fatal("inventory endpoint identity was not preserved")
	}
	if findCandidate(t, first.Candidates, CandidateParameter, parameter.Name).ParameterIdentity != parameter.Identity {
		t.Fatal("inventory parameter identity was not preserved")
	}
	if findCandidate(t, first.Candidates, CandidateAPIVersion, "https://example.test/api/v2/users").Source != SourceHeuristic {
		t.Fatal("expected bounded API-version heuristic candidate")
	}
}

func TestBuildCandidatesFailsClosedForCrossProjectUnsafeAndSensitiveInput(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/items", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	base := Input{ProjectID: "alpha", BaseURL: "https://example.test", Inventory: endpointintelligence.Inventory{ProjectID: "alpha", Endpoints: []endpointintelligence.Endpoint{{Identity: endpoint.Identity, Method: endpoint.Method, URL: endpoint.URL}}}, Limits: DefaultLimits()}
	foreign := base
	foreign.Inventory.ProjectID = "beta"
	if _, err := Build(foreign); err == nil {
		t.Fatal("expected project isolation rejection")
	}
	unsafe := base
	unsafe.Seeds = []Seed{{Type: CandidatePath, Value: "/../etc/passwd", Source: SourceManual, EvidenceID: "manual"}}
	if _, err := Build(unsafe); err == nil {
		t.Fatal("expected traversal rejection")
	}
	secret := base
	secret.Seeds = []Seed{{Type: CandidateParameterValue, Value: "Bearer abc.def.ghi", Source: SourceJavaScript, EvidenceID: "js:bundle"}}
	if _, err := Build(secret); err == nil {
		t.Fatal("expected secret-bearing value rejection")
	}
	wordlist := base
	wordlist.Wordlist = []string{"/openapi.json", "/.env"}
	if _, err := Build(wordlist); err == nil {
		t.Fatal("expected sensitive wordlist entry rejection")
	}
}

func TestSeedsFromStaticReportUsesExistingR6ReferencesWithoutValuesOrExecution(t *testing.T) {
	report := jsanalysis.StaticReport{SourceID: "javascript:https://example.test/app.js", URLs: []jsanalysis.StaticReference{{Value: "/api/v1/users", Confidence: "high", Evidence: "fetch"}}, Routes: []jsanalysis.StaticReference{{Value: "/docs", Confidence: "medium", Evidence: "route"}}, Parameters: []jsanalysis.StaticParameter{{Name: "page", Endpoint: "/api/v1/users", Location: "query", Confidence: "medium"}, {Name: "authorization", Endpoint: "/api/v1/users", Location: "header", SensitiveReference: true}}}
	seeds := SeedsFromStaticReport(report, 8)
	if len(seeds) != 3 {
		t.Fatalf("seeds=%#v", seeds)
	}
	if seeds[0].Source != SourceJavaScript || seeds[0].EvidenceID != report.SourceID {
		t.Fatalf("unexpected source provenance=%#v", seeds[0])
	}
	for _, seed := range seeds {
		if seed.Value == "authorization" || seed.Value == "" {
			t.Fatalf("sensitive or empty JavaScript seed=%#v", seed)
		}
	}
}

func findCandidate(t *testing.T, candidates []DiscoveryCandidate, kind CandidateType, value string) DiscoveryCandidate {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Type == kind && candidate.Value == value {
			return candidate
		}
	}
	t.Fatalf("candidate type=%q value=%q not found in %#v", kind, value, candidates)
	return DiscoveryCandidate{}
}
