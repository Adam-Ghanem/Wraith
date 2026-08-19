package requestmutation

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func BenchmarkBuildPlanDefaultStrategies(b *testing.B) {
	endpoint, err := evidence.NewEndpoint("alpha", "POST", "https://example.test/api/items/{id}?page=1", time.Unix(1, 0))
	if err != nil {
		b.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "page", time.Unix(1, 0))
	if err != nil {
		b.Fatal(err)
	}
	input := PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, Limits: DefaultLimits()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := BuildPlan(input); err != nil {
			b.Fatal(err)
		}
	}
}
