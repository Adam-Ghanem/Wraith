package smartdiscovery

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func BenchmarkBuildEvidenceDrivenCandidates(b *testing.B) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/api/v1/users", time.Unix(1, 0))
	if err != nil {
		b.Fatal(err)
	}
	inventory := endpointintelligence.Inventory{ProjectID: "alpha", Endpoints: []endpointintelligence.Endpoint{{Identity: endpoint.Identity, Method: endpoint.Method, URL: endpoint.URL}}}
	input := Input{ProjectID: "alpha", BaseURL: "https://example.test", Inventory: inventory, Seeds: []Seed{{Type: CandidatePath, Value: "/api/v1/users", Source: SourceJavaScript, EvidenceID: "js"}}, Heuristics: true, Limits: DefaultLimits()}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := Build(input); err != nil {
			b.Fatal(err)
		}
	}
}
