package injection

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

func BenchmarkBuildPlanSafeSQL(b *testing.B) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		b.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		b.Fatal(err)
	}
	input := PlanInput{ProjectID: "alpha", RunID: "run", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL}, Profile: ProfileSafe, Limits: DefaultLimits()}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := BuildPlan(input); err != nil {
			b.Fatal(err)
		}
	}
}
