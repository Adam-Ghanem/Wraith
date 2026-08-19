package injection

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

func FuzzBuildPlanNeverPanicsOnClassText(f *testing.F) {
	f.Add("sql", "safe")
	f.Add("../../path", "deep")
	f.Fuzz(func(t *testing.T, classText, profileText string) {
		endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{InjectionClass(classText)}, Profile: Profile(profileText), Limits: DefaultLimits()})
	})
}

func FuzzAnalyzeNeverCreatesFinding(f *testing.F) {
	f.Add("database syntax error")
	f.Fuzz(func(t *testing.T, body string) {
		signal := Analyze(InjectionTest{TestID: "test", ProjectID: "alpha", InjectionClass: ClassSQL, PayloadID: "sql-quote"}, ResponseSnapshot{StatusCode: 200, Body: []byte("ok")}, ResponseSnapshot{StatusCode: 500, Body: []byte(body)})
		if signal.FindingID != "" {
			t.Fatalf("finding=%#v", signal)
		}
	})
}
