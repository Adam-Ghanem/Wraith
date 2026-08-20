package findingvalidation

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

type recordingClient struct {
	requests  []httpengine.Request
	responses []httpengine.Response
}

func (client *recordingClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	response := client.responses[0]
	client.responses = client.responses[1:]
	return response, nil
}

type recordingR8 struct{ calls int }

func (submitter *recordingR8) Submit(_ context.Context, _ ValidationCandidate, _ ValidationResult, _ evidence.Endpoint, _ httpengine.Response) ([]string, error) {
	submitter.calls++
	return []string{"observation-1"}, nil
}

type recordingR9 struct {
	calls      int
	candidates []FindingCandidate
}

func (submitter *recordingR9) Submit(_ context.Context, candidate FindingCandidate) (string, error) {
	submitter.calls++
	submitter.candidates = append(submitter.candidates, candidate)
	return "correlation-1", nil
}

type recordingPolicy struct{ checks int }

func (checker *recordingPolicy) Recheck(_ context.Context, projectID string, endpoint evidence.Endpoint) error {
	if projectID != endpoint.ProjectID {
		return ErrPolicyDenied
	}
	checker.checks++
	return nil
}

func TestRunRequiresExplicitOptInAndHandsOnlyValidatedCandidateToR8AndR9(t *testing.T) {
	candidate, plan, template, parameter := validationFixture(t)
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200, Body: []byte("ok")}, {StatusCode: 500, Body: []byte("database syntax error")}, {StatusCode: 200, Body: []byte("ok")}, {StatusCode: 500, Body: []byte("database syntax error")}}}
	r8, r9, policy := &recordingR8{}, &recordingR9{}, &recordingPolicy{}
	dependencies := RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Policy: policy, R8: r8, R9: r9}
	passive, err := Run(context.Background(), candidate, plan, template, parameter, dependencies, RunOptions{Authorized: true, Execute: false, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil || passive.RequestsSent != 0 || len(client.requests) != 0 {
		t.Fatalf("passive=%#v err=%v requests=%#v", passive, err, client.requests)
	}
	run, err := Run(context.Background(), candidate, plan, template, parameter, dependencies, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if run.Result.Status != StatusValidated || run.RequestsSent != 4 || policy.checks != 4 || r8.calls != 1 || r9.calls != 1 || len(r9.candidates) != 1 || run.CorrelationID != "correlation-1" || budget.Used().Requests != 4 {
		t.Fatalf("run=%#v policy=%#v r8=%#v r9=%#v budget=%#v", run, policy, r8, r9, budget.Used())
	}
	if run.Metrics.SignalsReceived != 1 || run.Metrics.ValidationsStarted != 1 || run.Metrics.ValidationsCompleted != 1 || run.Metrics.Validated != 1 || run.Metrics.RequestsUsed != 4 || run.Metrics.FindingCandidates != 1 || run.Metrics.CorrelatedFindings != 1 {
		t.Fatalf("metrics=%#v", run.Metrics)
	}
}

func TestRunStopsOnRateLimitBeforeR8OrR9(t *testing.T) {
	candidate, plan, template, parameter := validationFixture(t)
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200, Body: []byte("ok")}, {StatusCode: 429}}}
	r8, r9, policy := &recordingR8{}, &recordingR9{}, &recordingPolicy{}
	run, err := Run(context.Background(), candidate, plan, template, parameter, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Policy: policy, R8: r8, R9: r9}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err == nil || run.Result.Status != StatusInconclusive || len(client.requests) != 2 || r8.calls != 0 || r9.calls != 0 {
		t.Fatalf("run=%#v err=%v r8=%#v r9=%#v", run, err, r8, r9)
	}
}

func TestRunRejectsUnsupportedCandidateProfileBeforeDispatch(t *testing.T) {
	candidate, plan, template, parameter := validationFixture(t)
	candidate.Profile = Profile("unbounded")
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{}
	policy := &recordingPolicy{}
	if _, err := Run(context.Background(), candidate, plan, template, parameter, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Policy: policy, R8: &recordingR8{}, R9: &recordingR9{}}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil || len(client.requests) != 0 || policy.checks != 0 {
		t.Fatalf("err=%v requests=%#v policy=%#v", err, client.requests, policy)
	}
}

func validationFixture(t *testing.T) (ValidationCandidate, injection.Plan, requestmutation.RequestTemplate, evidence.Parameter) {
	t.Helper()
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	template := requestmutation.RequestTemplate{Endpoint: endpoint}
	plan, err := injection.BuildPlan(injection.PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: template, Parameter: parameter, Classes: []injection.InjectionClass{injection.ClassSQL}, Profile: injection.ProfileStandard, Limits: injection.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	test := plan.Tests[0]
	signal := injection.InjectionSignal{SignalID: "signal-1", TestID: test.TestID, Class: test.InjectionClass, Type: injection.SignalError, Confidence: injection.ConfidencePossible, Fingerprint: "signal-fingerprint"}
	candidate, err := NewCandidate(CandidateInput{ProjectID: "alpha", RunID: "run-1", Signal: signal, Endpoint: endpoint, Parameter: parameter, Profile: ProfileStandard, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return candidate, plan, template, parameter
}
