package injection

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
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

type recordingEvidenceSink struct {
	endpoints    []evidence.Endpoint
	observations []evidence.Observation
}

func (sink *recordingEvidenceSink) UpsertEndpoint(_ context.Context, endpoint evidence.Endpoint) (evidence.Endpoint, error) {
	sink.endpoints = append(sink.endpoints, endpoint)
	return endpoint, nil
}

func (sink *recordingEvidenceSink) AppendObservation(_ context.Context, observation evidence.Observation) error {
	sink.observations = append(sink.observations, observation)
	return nil
}

type recordingValidator struct{ signals []InjectionSignal }

func (validator *recordingValidator) Submit(_ context.Context, signal InjectionSignal) error {
	validator.signals = append(validator.signals, signal)
	return nil
}

func TestRunRequiresExplicitOptInAndUsesR3BudgetForBaselineAndPayload(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	plan, err := BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL}, Profile: ProfileSafe, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200, ContentType: "text/html", Body: []byte("ok")}, {StatusCode: 500, ContentType: "text/html", Body: []byte("database syntax error")}}}
	dependencies := RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency}
	passive, err := Run(context.Background(), plan, dependencies, RunOptions{Authorized: true, Execute: false, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil || passive.RequestsSent != 0 || len(client.requests) != 0 {
		t.Fatalf("passive run=%#v err=%v requests=%#v", passive, err, client.requests)
	}
	run, err := Run(context.Background(), plan, dependencies, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 2 || client.requests[0].Method != "GET" || client.requests[0].Source != "injection.r11.3.baseline" || client.requests[1].Source != "injection.r11.3.test" || len(run.Signals) != 1 || run.Signals[0].Type != SignalError || run.FindingsCreated != 0 {
		t.Fatalf("client=%#v run=%#v", client.requests, run)
	}
	if budget.Used().Requests != 2 {
		t.Fatalf("budget=%#v", budget.Used())
	}
}

func TestRunRejectsUnauthorizedUnsafeMethodAndCancelledContext(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "POST", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	plan, err := BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL}, Profile: ProfileSafe, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), plan, RunDependencies{}, RunOptions{Authorized: false, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil {
		t.Fatal("expected authorization rejection")
	}
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{}
	if _, err := Run(context.Background(), plan, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil || len(client.requests) != 0 {
		t.Fatalf("unsafe method run err=%v requests=%#v", err, client.requests)
	}
	contextCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	endpoint.Method = "GET"
	plan.template.Endpoint = endpoint
	if _, err := Run(contextCancelled, plan, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestRunPersistsRedactedInjectionSignalEvidence(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	plan, err := BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL}, Profile: ProfileSafe, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	sink := &recordingEvidenceSink{}
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200, Body: []byte("ok")}, {StatusCode: 500, Body: []byte("database syntax error")}}}
	_, err = Run(context.Background(), plan, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Evidence: sink}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 1 || len(sink.observations) != 1 || !sink.observations[0].Redacted || sink.observations[0].Source != "injection.r11.3.result" {
		t.Fatalf("sink endpoints=%#v observations=%#v", sink.endpoints, sink.observations)
	}
}

func TestRunStopsCleanlyOnRateLimitResponse(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	plan, err := BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL, ClassSSTI}, Profile: ProfileSafe, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200}, {StatusCode: 429}}}
	run, err := Run(context.Background(), plan, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err == nil || len(client.requests) != 2 || run.TestsExecuted != 0 {
		t.Fatalf("err=%v requests=%#v run=%#v", err, client.requests, run)
	}
}

func TestRunHandsSignalsToValidationWithoutCreatingFindings(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	plan, err := BuildPlan(PlanInput{ProjectID: "alpha", RunID: "run-1", Authorized: true, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: []InjectionClass{ClassSQL}, Profile: ProfileSafe, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(20)
	concurrency, _ := pentest.NewConcurrencyController(1)
	validator := &recordingValidator{}
	client := &recordingClient{responses: []httpengine.Response{{StatusCode: 200}, {StatusCode: 500, Body: []byte("database syntax error")}}}
	run, err := Run(context.Background(), plan, RunDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Validation: validator}, RunOptions{Authorized: true, Execute: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(validator.signals) != 1 || validator.signals[0].SignalID != run.Signals[0].SignalID || run.FindingsCreated != 0 {
		t.Fatalf("validator=%#v run=%#v", validator.signals, run)
	}
}
