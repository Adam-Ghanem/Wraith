package fuzzing

import (
	"strings"
	"testing"
)

func TestBuildPlanProvidesBoundedDeterministicProfileCounts(t *testing.T) {
	cases := []struct {
		profile Profile
		count   int
	}{{ProfileMinimal, 3}, {ProfileBoundary, 10}, {ProfileEncoding, 5}, {ProfileType, 6}, {ProfileCombined, 24}}
	for _, test := range cases {
		t.Run(string(test.profile), func(t *testing.T) {
			plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api/users", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api/users?id=old"}, Profile: test.profile, Limits: DefaultLimits()})
			if err != nil || plan.Estimated != test.count || len(plan.Requests) != test.count {
				t.Fatalf("plan=%#v err=%v", plan, err)
			}
			for _, request := range plan.Requests {
				if strings.Contains(strings.ToLower(request.Mutation.Input), "password") || request.Mutation.SafetyClass != SafetyGeneric {
					t.Fatalf("unsafe mutation=%#v", request.Mutation)
				}
			}
		})
	}
}

func TestBuildPlanTransformsOnlyExplicitPathJSONFormOrSafeHeader(t *testing.T) {
	cases := []struct {
		name     string
		target   FuzzTarget
		template RequestTemplate
		assert   func(*testing.T, RequestTemplate)
	}{
		{"path", FuzzTarget{EndpointIdentity: "GET https://example.test/users/{id}", ParameterName: "id", Location: LocationPath}, RequestTemplate{Method: "GET", URL: "https://example.test/users/{id}"}, func(t *testing.T, template RequestTemplate) {
			if template.URL != "https://example.test/users/" {
				t.Fatalf("url=%q", template.URL)
			}
		}},
		{"json", FuzzTarget{EndpointIdentity: "POST https://example.test/users", ParameterName: "user.name", Location: LocationJSON}, RequestTemplate{Method: "POST", URL: "https://example.test/users", ContentType: "application/json", Body: []byte(`{"user":{"name":"old","keep":true}}`)}, func(t *testing.T, template RequestTemplate) {
			if string(template.Body) != `{"user":{"keep":true,"name":""}}` {
				t.Fatalf("body=%s", template.Body)
			}
		}},
		{"form", FuzzTarget{EndpointIdentity: "POST https://example.test/users", ParameterName: "name", Location: LocationForm}, RequestTemplate{Method: "POST", URL: "https://example.test/users", ContentType: "application/x-www-form-urlencoded", Body: []byte("name=old&keep=1")}, func(t *testing.T, template RequestTemplate) {
			if string(template.Body) != "keep=1&name=" {
				t.Fatalf("body=%s", template.Body)
			}
		}},
		{"header", FuzzTarget{EndpointIdentity: "GET https://example.test/users", ParameterName: "Accept", Location: LocationHeader}, RequestTemplate{Method: "GET", URL: "https://example.test/users", Headers: map[string][]string{"User-Agent": {"Wraith"}}}, func(t *testing.T, template RequestTemplate) {
			if template.Headers["Accept"][0] != "" || template.Headers["User-Agent"][0] != "Wraith" {
				t.Fatalf("headers=%#v", template.Headers)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: test.target, Template: test.template, Profile: ProfileMinimal, Limits: DefaultLimits(), AllowUnsafeMethods: true, ConfirmUnsafe: true})
			if err != nil {
				t.Fatal(err)
			}
			test.assert(t, plan.Requests[0].Template)
		})
	}
}
