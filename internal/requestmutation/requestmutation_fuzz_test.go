package requestmutation

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func FuzzBuildPlanDoesNotPanicOrCrossProjectBoundaries(f *testing.F) {
	f.Add("item", "https://example.test/items/{id}?page=1", true)
	f.Add("profile.name", "https://example.test/api/profile", false)
	f.Fuzz(func(t *testing.T, parameterName, rawURL string, authorized bool) {
		endpoint, err := evidence.NewEndpoint("alpha", "GET", rawURL, time.Unix(1, 0))
		if err != nil {
			return
		}
		parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, parameterName, time.Unix(1, 0))
		if err != nil {
			return
		}
		plan, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: authorized, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()})
		if err == nil && (!authorized || plan.ProjectID != "alpha" || len(plan.Variants) != 2) {
			t.Fatalf("unsafe plan=%#v", plan)
		}
	})
}

func FuzzSensitiveHeaderNamesAreNeverAccepted(f *testing.F) {
	f.Add("Authorization")
	f.Add("Cookie")
	f.Add("X-Request-ID")
	f.Fuzz(func(t *testing.T, header string) {
		endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/items/{id}", time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationHeader, header, time.Unix(1, 0))
		if err != nil {
			return
		}
		_, err = BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()})
		if sensitiveHeader(header) && err == nil {
			t.Fatalf("accepted sensitive header %q", header)
		}
	})
}
