package validation

import (
	"net/http"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestDefaultValidatorsEmitDeterministicPassiveEvidence(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.test/api", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	input := Input{ProjectID: "project-a", Endpoint: endpoint, ObservedAt: time.Unix(0, 0).UTC(), StatusCode: http.StatusInternalServerError, Headers: http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Credentials": {"true"}, "Set-Cookie": {"sid=opaque"}, "Server": {"nginx/1.25.4"}}, Body: []byte("panic: runtime error\n at /srv/app/main.go:42")}
	results, err := Run(input, DefaultValidators())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 8 || results[0].ValidatorID != "cookies" || results[0].Lifecycle != LifecycleObserved || results[0].ReproducibilityKey == "" {
		t.Fatalf("results=%#v", results)
	}
}

func TestRunRejectsCrossProjectEndpoint(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("project-b", http.MethodGet, "https://example.test/", time.Unix(0, 0).UTC())
	_, err := Run(Input{ProjectID: "project-a", Endpoint: endpoint, ObservedAt: time.Unix(0, 0).UTC()}, DefaultValidators())
	if err == nil {
		t.Fatal("expected project mismatch")
	}
}

func TestRunRejectsOversizedResponseEvidence(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.test/", time.Unix(0, 0).UTC())
	_, err := Run(Input{ProjectID: "project-a", Endpoint: endpoint, ObservedAt: time.Unix(0, 0).UTC(), Body: make([]byte, 1<<20+1)}, DefaultValidators())
	if err == nil {
		t.Fatal("expected oversized evidence to be rejected")
	}
}

func TestSecurityHeadersValidatorFlagsMissingNoSniff(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.test/", time.Unix(0, 0).UTC())
	results, err := Run(Input{ProjectID: "project-a", Endpoint: endpoint, ObservedAt: time.Unix(0, 0).UTC(), Headers: http.Header{}}, []Validator{headerValidator{}})
	if err != nil || len(results) != 2 || results[1].RuleID != "missing-nosniff" {
		t.Fatalf("results=%#v err=%v", results, err)
	}
}

func TestLifecycleStatesAreExplicitAndObservedIsTheOnlyAutomaticState(t *testing.T) {
	for _, lifecycle := range []Lifecycle{LifecycleObserved, LifecycleAccepted, LifecycleResolved, LifecycleFalsePositive} {
		if !lifecycle.Valid() {
			t.Fatalf("lifecycle %q should be valid", lifecycle)
		}
	}
	if Lifecycle("confirmed").Valid() {
		t.Fatal("unexpected automatic confirmation lifecycle")
	}
}
