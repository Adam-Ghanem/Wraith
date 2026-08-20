package findingvalidation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

func TestNewCandidateIsProjectScopedBoundedAndSecretFree(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	signal := injection.InjectionSignal{SignalID: "signal-1", TestID: "test-1", Class: injection.ClassSQL, Type: injection.SignalError, Confidence: injection.ConfidencePossible, Fingerprint: "signal-fingerprint", Metadata: map[string]string{"request_value": "secret-canary"}}
	first, err := NewCandidate(CandidateInput{ProjectID: "alpha", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCandidate(CandidateInput{ProjectID: "alpha", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if first.ValidationID != second.ValidationID || first.Fingerprint != second.Fingerprint || first.Status != StatusPending || first.InjectionClass != injection.ClassSQL {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-canary") || strings.Contains(string(encoded), "request_value") {
		t.Fatalf("candidate leaked signal metadata: %s", encoded)
	}
}

func TestNewCandidateRejectsCrossProjectAndMalformedSignal(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	signal := injection.InjectionSignal{SignalID: "signal-1", TestID: "test-1", Class: injection.ClassSQL, Type: injection.SignalError, Confidence: injection.ConfidencePossible, Fingerprint: "signal-fingerprint"}
	if _, err := NewCandidate(CandidateInput{ProjectID: "beta", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(2, 0)}); err == nil {
		t.Fatal("expected cross-project rejection")
	}
	signal.SignalID = ""
	if _, err := NewCandidate(CandidateInput{ProjectID: "alpha", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(2, 0)}); err == nil {
		t.Fatal("expected malformed signal rejection")
	}
	signal.SignalID, signal.Type = "signal-1", injection.SignalType("unsupported")
	if _, err := NewCandidate(CandidateInput{ProjectID: "alpha", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(2, 0)}); err == nil {
		t.Fatal("expected unsupported signal type rejection")
	}
}

func TestCompareFiltersDynamicOnlyDifference(t *testing.T) {
	baseline := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("request at 2026-08-19T10:00:00Z")}
	response := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("request at 2026-08-20T11:00:00Z")}
	diff := Compare(baseline, response, "canary")
	if !diff.DynamicOnly || diff.SecurityRelevant || diff.FingerprintChanged {
		t.Fatalf("diff=%#v", diff)
	}
}

func TestCompareTreatsGenericFiveHundredAsInfrastructureInstability(t *testing.T) {
	baseline := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("ok")}
	response := ResponseSnapshot{StatusCode: 500, ContentType: "text/html", Body: []byte("upstream unavailable")}
	diff := Compare(baseline, response, "canary")
	if diff.SecurityRelevant || !diff.InfrastructureUnstable {
		t.Fatalf("diff=%#v", diff)
	}
}

func TestAssessRequiresRepeatableSecurityEvidenceBeforeFindingCandidate(t *testing.T) {
	candidate := ValidationCandidate{ValidationID: "validation-1", ProjectID: "alpha", RunID: "run-1", SignalID: "signal-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", InjectionClass: injection.ClassSQL, Fingerprint: "candidate-fingerprint"}
	result := Assess(candidate, []ValidationDiff{{SecurityRelevant: true, Fingerprint: "repeatable"}, {SecurityRelevant: true, Fingerprint: "repeatable"}})
	if result.Status != StatusValidated || result.Repeatability != Repeatable || result.Confidence != ConfidenceHigh {
		t.Fatalf("result=%#v", result)
	}
	finding, err := NewFindingCandidate(candidate, result, []string{"observation-1", "observation-2"})
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != FindingCandidateValidated || finding.SeverityHint == "" || finding.Fingerprint == "" {
		t.Fatalf("finding=%#v", finding)
	}
	if _, err := NewFindingCandidate(candidate, ValidationResult{Status: StatusInconclusive}, nil); err == nil {
		t.Fatal("expected inconclusive finding rejection")
	}
}
