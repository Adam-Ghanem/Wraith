package fuzzing

import (
	"net/http"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestAnalyzeJobMapsResponsesToMutationsDeterministically(t *testing.T) {
	plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api?id=old"}, Profile: ProfileMinimal, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	job := FuzzJob{State: JobCompleted, Results: []FuzzResult{{MutationID: "minimal/zero", Response: httpengine.Response{StatusCode: http.StatusOK, ContentType: "text/plain", Body: []byte("0")}}, {MutationID: "minimal/empty", Response: httpengine.Response{StatusCode: http.StatusInternalServerError, ContentType: "text/plain", Body: []byte("type error")}}}}
	baseline := httpengine.Response{StatusCode: http.StatusOK, ContentType: "text/plain", Body: []byte("baseline")}
	results, err := AnalyzeJob(plan, job, &baseline)
	if err != nil || len(results) != 2 || results[0].Mutation.ID != "minimal/empty" || !containsString(results[0].Analysis.ErrorClasses, "server_error") || results[1].Mutation.ID != "minimal/zero" {
		t.Fatalf("results=%#v err=%v", results, err)
	}
}
