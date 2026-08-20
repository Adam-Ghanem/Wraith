package injection

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

func TestBuildPlanProducesBoundedProjectScopedSecretFreeTests(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	template := requestmutation.RequestTemplate{Endpoint: endpoint}
	input := PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: template, Parameter: parameter, Classes: []InjectionClass{ClassSQL, ClassSSTI}, Profile: ProfileSafe, Limits: DefaultLimits()}
	first, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || len(first.Tests) != 2 || first.EstimatedRequests != 6 {
		t.Fatalf("plan first=%#v second=%#v", first, second)
	}
	for _, test := range first.Tests {
		if test.ProjectID != "alpha" || test.ParameterID != parameter.Identity || test.BaselineVariantID == "" || test.Status != TestPlanned || test.PayloadID == "" {
			t.Fatalf("test=%#v", test)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "{{7*7}}") || strings.Contains(string(encoded), "'") {
		t.Fatalf("raw payload leaked in plan=%s", encoded)
	}
}

func TestBuildPlanRejectsCrossProjectSensitiveHeaderAndExplosiveLimits(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	query, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	foreign := requestmutation.RequestTemplate{Endpoint: endpoint}
	if _, err := BuildPlan(PlanInput{ProjectID: "beta", Authorized: true, Template: foreign, Parameter: query, Profile: ProfileSafe, Limits: DefaultLimits()}); err == nil {
		t.Fatal("expected project mismatch")
	}
	header, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationHeader, "Authorization", time.Unix(1, 0))
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: foreign, Parameter: header, Classes: []InjectionClass{ClassHeader}, Profile: ProfileSafe, Limits: DefaultLimits()}); err == nil {
		t.Fatal("expected sensitive header rejection")
	}
	limits := DefaultLimits()
	limits.MaxTestsPerParameter = 1
	if _, err := BuildPlan(PlanInput{ProjectID: "alpha", Authorized: true, Template: foreign, Parameter: query, Classes: []InjectionClass{ClassSQL, ClassSSTI}, Profile: ProfileSafe, Limits: limits}); err == nil {
		t.Fatal("expected test-limit rejection")
	}
}

func TestAnalyzeProducesSignalsNotFindings(t *testing.T) {
	baseline := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("ok")}
	response := ResponseSnapshot{StatusCode: 500, ContentType: "text/html", Body: []byte("database syntax error")}
	signal := Analyze(InjectionTest{TestID: "test-1", ProjectID: "alpha", InjectionClass: ClassSQL, PayloadID: "sql-quote"}, baseline, response)
	if signal.Type != SignalError || signal.Confidence != ConfidencePossible || signal.TestID != "test-1" || signal.FindingID != "" {
		t.Fatalf("signal=%#v", signal)
	}
}

func TestAnalyzeUsesMemoryOnlyPayloadForReflectionSignal(t *testing.T) {
	baseline := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("ok")}
	response := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("echo wraith-canary")}
	signal := Analyze(InjectionTest{TestID: "test-1", ProjectID: "alpha", InjectionClass: ClassCommand, PayloadID: "command-canary", PayloadValue: "wraith-canary"}, baseline, response)
	if signal.Type != SignalReflection || signal.FindingID != "" {
		t.Fatalf("signal=%#v", signal)
	}
}
