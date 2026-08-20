package assessmentexec

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

func BenchmarkEngineDryRun(b *testing.B) {
	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "benchmark", Target: "https://example.test", ScopeVersion: "scope-v1", Authorized: true, Profile: assessment.ProfileSafe, ExpiresAt: now.Add(time.Hour), Limits: assessment.Limits{MaxRequests: 32, MaxConcurrency: 1, MaxRate: 10, MaxDuration: time.Minute}, CreatedAt: now})
	if err != nil {
		b.Fatal(err)
	}
	plan.Tasks = plan.Tasks[:2]
	registry := testRegistryBenchmark(b, func(assessment.Task) error { return nil })
	deps := testDependenciesBenchmark(b)
	engine := NewEngine(registry, deps)
	request := ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID, DryRun: true}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := engine.Execute(context.Background(), request); err != nil {
			b.Fatal(err)
		}
	}
}

func testRegistryBenchmark(b *testing.B, run func(assessment.Task) error) *assessment.AdapterRegistry {
	b.Helper()
	registry, err := assessment.NewAdapterRegistry(
		assessment.TypedAdapter{TaskType: assessment.TaskCrawl, Adapter: adapterFunc{owner: "benchmark.crawl", run: run}},
		assessment.TypedAdapter{TaskType: assessment.TaskEndpoints, Adapter: adapterFunc{owner: "benchmark.endpoints", run: run}},
	)
	if err != nil {
		b.Fatal(err)
	}
	return &registry
}

func testDependenciesBenchmark(b *testing.B) Dependencies {
	b.Helper()
	limits := pentest.DefaultLimits()
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		b.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(limits.MaxConcurrency)
	if err != nil {
		b.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(limits.MaxRate)
	if err != nil {
		b.Fatal(err)
	}
	return Dependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: time.Now, Authorize: func(context.Context, assessment.ScopeSnapshot) error { return nil }}
}
