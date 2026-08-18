package fuzzing

import (
	"net/http"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func FuzzBuildPlanNeverPanics(f *testing.F) {
	f.Add("id", "query", "minimal")
	f.Add("user.name", "json", "type")
	f.Fuzz(func(t *testing.T, name, location, profile string) {
		limits := DefaultLimits()
		template := RequestTemplate{Method: "GET", URL: "https://example.test/api?id=old"}
		if location == string(LocationJSON) {
			template = RequestTemplate{Method: "POST", URL: "https://example.test/api", ContentType: "application/json", Body: []byte(`{"user":{"name":"old"}}`)}
		}
		_, _ = BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: name, Location: Location(location)}, Template: template, Profile: Profile(profile), Limits: limits, AllowUnsafeMethods: true, ConfirmUnsafe: true})
	})
}

func FuzzAnalyzeResponseNeverPanics(f *testing.F) {
	f.Add([]byte("type error"), "a")
	f.Fuzz(func(t *testing.T, body []byte, marker string) {
		_ = AnalyzeResponse(nil, Mutation{ID: "fuzz/input", Category: "boundary", Value: marker, SafetyClass: SafetyGeneric}, httpengine.Response{StatusCode: http.StatusInternalServerError, ContentType: "text/plain", Body: body, Headers: http.Header{"X-Test": {marker}}})
	})
}
