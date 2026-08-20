package requestmutation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestBuildPlanCreatesDeterministicImmutableVariantsAcrossSupportedLocations(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "POST", "https://example.test/api/items/{id}?page=1", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	query, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "page", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	input := PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint, Headers: map[string][]string{"Accept-Language": {"en"}}, Body: []byte(`{"page":1,"nested":{"flag":true}}`), ContentType: "application/json"}, Target: query, Strategies: []Strategy{StrategyEmpty, StrategyNegative, StrategyUnicode}, Limits: DefaultLimits()}
	first, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Variants) != 4 || first.Fingerprint != second.Fingerprint {
		t.Fatalf("unexpected plan first=%#v second=%#v", first, second)
	}
	if first.Variants[0].Strategy != StrategyBaseline || first.Variants[1].Strategy != StrategyEmpty {
		t.Fatalf("unexpected variant order=%#v", first.Variants)
	}
	if first.Variants[1].Template.Endpoint.URL == input.Template.Endpoint.URL {
		t.Fatal("query variant did not change the request URL")
	}
	if input.Template.Endpoint.URL != endpoint.URL || !bytes.Equal(input.Template.Body, []byte(`{"page":1,"nested":{"flag":true}}`)) {
		t.Fatal("BuildPlan mutated the caller template")
	}
	if got := first.Variants[1].Template.Endpoint.URL; got == first.Variants[2].Template.Endpoint.URL {
		t.Fatalf("different strategies produced duplicate variants: %q", got)
	}
}

func TestBuildPlanSupportsPathFormJSONAndSafeHeaderMutations(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "POST", "https://example.test/items/{id}", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, contentType, body string
		location                evidence.ParameterLocation
		parameter               string
	}{
		{name: "path", location: evidence.ParameterLocationPath, parameter: "id"},
		{name: "form", contentType: "application/x-www-form-urlencoded", body: "name=alpha", location: evidence.ParameterLocationBody, parameter: "name"},
		{name: "json", contentType: "application/json", body: `{"profile":{"name":"alpha"}}`, location: evidence.ParameterLocationJSON, parameter: "profile.name"},
		{name: "header", location: evidence.ParameterLocationHeader, parameter: "Accept-Language"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameter, err := evidence.NewParameter("alpha", endpoint, test.location, test.parameter, time.Unix(1, 0))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint, Headers: map[string][]string{"Accept-Language": {"en"}}, Body: []byte(test.body), ContentType: test.contentType}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Variants) != 2 || plan.Variants[1].Fingerprint == plan.Variants[0].Fingerprint {
				t.Fatalf("variants=%#v", plan.Variants)
			}
		})
	}
}

func TestBuildPlanFailsClosedForUnauthorizedCrossProjectSensitiveOrUnboundedInput(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/items/{id}", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationPath, "id", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	base := PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()}
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: false, Template: base.Template, Target: parameter, Strategies: base.Strategies, Limits: base.Limits}); err == nil {
		t.Fatal("expected authorization rejection")
	}
	foreign := parameter
	foreign.ProjectID = "beta"
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: base.Template, Target: foreign, Strategies: base.Strategies, Limits: base.Limits}); err == nil {
		t.Fatal("expected project-isolation rejection")
	}
	sensitive := base.Template
	sensitive.Headers = map[string][]string{"Authorization": {"Bearer not-for-planning"}}
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: sensitive, Target: parameter, Strategies: base.Strategies, Limits: base.Limits}); err == nil {
		t.Fatal("expected sensitive header rejection")
	}
	limits := DefaultLimits()
	limits.MaxVariants = 1
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: base.Template, Target: parameter, Strategies: base.Strategies, Limits: limits}); err == nil {
		t.Fatal("expected variant limit rejection")
	}
}

func TestBuildPlanKeepsCookieContextMemoryOnlyAndImmutable(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/items/{id}", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationPath, "id", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	input := PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint, Cookies: map[string]string{"session": "memory-only-secret"}}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()}
	plan, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Variants[1].Template.Cookies["session"] != "memory-only-secret" {
		t.Fatalf("cookie context missing from variant=%#v", plan.Variants[1].Template.Cookies)
	}
	plan.Variants[1].Template.Cookies["session"] = "changed"
	if input.Template.Cookies["session"] != "memory-only-secret" {
		t.Fatal("variant mutation modified caller cookie context")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "memory-only-secret") || strings.Contains(string(encoded), "session") {
		t.Fatalf("serialized plan leaked cookie context: %s", encoded)
	}
}

func TestBuildPlanRejectsSecretLikeCustomHeaders(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/items/{id}", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationHeader, "X-Secret-Key", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, Strategies: []Strategy{StrategyEmpty}, Limits: DefaultLimits()}); err == nil {
		t.Fatal("expected secret-like header rejection")
	}
}
