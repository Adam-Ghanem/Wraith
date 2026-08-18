package fuzzing

import (
	"net/http"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func BenchmarkBuildPlanCombinedQuery(b *testing.B) {
	input := PlanInput{ProjectID: "benchmark", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api?id=old&keep=1"}, Profile: ProfileCombined, Limits: DefaultLimits()}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := BuildPlan(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeResponse(b *testing.B) {
	response := httpengine.Response{StatusCode: http.StatusInternalServerError, ContentType: "application/json", Headers: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"error":"type error","time":"2026-08-18T00:00:00Z"}`)}
	mutation := Mutation{ID: "benchmark", Category: "boundary", Value: "a", SafetyClass: SafetyGeneric}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		_ = AnalyzeResponse(nil, mutation, response)
	}
}
