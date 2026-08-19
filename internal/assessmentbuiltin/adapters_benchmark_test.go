package assessmentbuiltin

import (
	"context"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func BenchmarkRegistryLookup(b *testing.B) {
	registry, err := NewRegistry(Dependencies{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, ok := registry.Owner(assessment.TaskDiscovery); !ok {
			b.Fatal("discovery owner is missing")
		}
	}
}

func BenchmarkEndpointAdapterDispatch(b *testing.B) {
	registry, err := NewRegistry(Dependencies{EndpointSource: inventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: "https://app.example.test/"}}}})
	if err != nil {
		b.Fatal(err)
	}
	taskContext := testTaskContext(b, assessment.TaskEndpoints)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := registry.Dispatch(context.Background(), taskContext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdapterResultValidation(b *testing.B) {
	registry, err := assessment.NewAdapterRegistry(assessment.TypedAdapter{TaskType: assessment.TaskEndpoints, Adapter: benchmarkResultAdapter{}})
	if err != nil {
		b.Fatal(err)
	}
	taskContext := testTaskContext(b, assessment.TaskEndpoints)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := registry.Dispatch(context.Background(), taskContext); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkResultAdapter struct{}

func (benchmarkResultAdapter) Owner() string { return "benchmark.result" }
func (benchmarkResultAdapter) Execute(_ context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
	return assessment.AdapterResult{Owner: "benchmark.result", TaskID: taskContext.Task.ID, EvidenceRefs: []string{"evidence-1"}, SignalCount: 1}, nil
}
