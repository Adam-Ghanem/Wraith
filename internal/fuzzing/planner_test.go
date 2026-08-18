package fuzzing

import (
	"reflect"
	"testing"
)

func TestBuildPlanIsDeterministicAndMutatesOnlySelectedQueryParameter(t *testing.T) {
	input := PlanInput{
		ProjectID: "project-a",
		Target:    FuzzTarget{EndpointIdentity: "GET https://example.test/api/users", ParameterName: "id", Location: LocationQuery},
		Template:  RequestTemplate{Method: "GET", URL: "https://example.test/api/users?id=old&keep=1"},
		Profile:   ProfileMinimal,
		Limits:    DefaultLimits(),
	}
	first, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(input)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("first=%#v second=%#v err=%v", first, second, err)
	}
	if len(first.Requests) != 3 || first.Requests[0].Template.URL != "https://example.test/api/users?id=&keep=1" || first.Requests[1].Template.URL != "https://example.test/api/users?id=a&keep=1" {
		t.Fatalf("plan=%#v", first)
	}
}

func TestBuildPlanRejectsSensitiveHeaderAndUnsafeMethodsWithoutExplicitConfirmation(t *testing.T) {
	base := PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api/users", ParameterName: "Accept", Location: LocationHeader}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api/users", Headers: map[string][]string{"Authorization": {"Bearer ignored"}}}, Profile: ProfileMinimal, Limits: DefaultLimits()}
	if _, err := BuildPlan(base); err == nil {
		t.Fatal("expected credential-header target rejection")
	}
	base.Target = FuzzTarget{EndpointIdentity: "POST https://example.test/api/users", ParameterName: "name", Location: LocationJSON}
	base.Template = RequestTemplate{Method: "POST", URL: "https://example.test/api/users", Body: []byte(`{"name":"old"}`), ContentType: "application/json"}
	if _, err := BuildPlan(base); err == nil {
		t.Fatal("expected unsafe-method rejection")
	}
}
