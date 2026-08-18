package fuzzing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type failingClient struct{}

func (failingClient) Do(context.Context, httpengine.Request) (httpengine.Response, error) {
	return httpengine.Response{}, errors.New("transport denied")
}

type delayedClient struct {
	active, maximum atomic.Int32
}

func (client *delayedClient) Do(context.Context, httpengine.Request) (httpengine.Response, error) {
	active := client.active.Add(1)
	for {
		maximum := client.maximum.Load()
		if active <= maximum || client.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	time.Sleep(15 * time.Millisecond)
	client.active.Add(-1)
	return httpengine.Response{StatusCode: http.StatusOK}, nil
}

type allowGateway struct{}

func (allowGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: projectID == "project-a", ProjectID: projectID, Target: target, Action: action}, nil
}

type denyGateway struct{}

func (denyGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: false, ProjectID: projectID, Target: target, Action: action}, policy.ErrOutOfScope
}

func TestRunExecutesBoundedPlanOnlyThroughR3Engine(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	engine := httpengine.NewEngine(httpengine.Config{Gateway: allowGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}, RequestTimeout: time.Second, MaxConcurrentRequests: 1})
	plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET " + server.URL + "/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: server.URL + "/api?id=old"}, Profile: ProfileMinimal, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	job, err := Run(context.Background(), engine, plan, ExecutionOptions{Timeout: time.Second, MaxDuration: 2 * time.Second})
	if err != nil || job.State != JobCompleted || job.Progress != 3 || calls.Load() != 3 {
		t.Fatalf("job=%#v calls=%d err=%v", job, calls.Load(), err)
	}
}

func TestRunCancelsBeforeAnyR3Request(t *testing.T) {
	context, cancel := context.WithCancel(context.Background())
	cancel()
	plan := FuzzPlan{ID: "plan", ProjectID: "project-a", Requests: []PlannedRequest{{Template: RequestTemplate{Method: "GET", URL: "https://example.test"}}}}
	job, err := Run(context, nil, plan, ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err == nil || job.State != JobCancelled || job.Progress != 0 {
		t.Fatalf("job=%#v err=%v", job, err)
	}
}

func TestRunHonorsBoundedConcurrency(t *testing.T) {
	plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api?id=old"}, Profile: ProfileMinimal, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	client := &delayedClient{}
	job, err := Run(context.Background(), client, plan, ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second, Concurrency: 2})
	if err != nil || job.State != JobCompleted || client.maximum.Load() != 2 || job.Progress != 3 {
		t.Fatalf("job=%#v maximum=%d err=%v", job, client.maximum.Load(), err)
	}
}

func TestRunReportsR3FailureWithoutMisclassifyingItAsCancellation(t *testing.T) {
	plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api?id=old"}, Profile: ProfileMinimal, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	job, err := Run(context.Background(), failingClient{}, plan, ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err == nil || job.State != JobFailed || job.Progress != 0 {
		t.Fatalf("job=%#v err=%v", job, err)
	}
}

func TestRunR3PolicyDenialNeverReachesTarget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	plan, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET " + server.URL + "/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: server.URL + "/api?id=old"}, Profile: ProfileMinimal, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: denyGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}, RequestTimeout: time.Second})
	job, err := Run(context.Background(), engine, plan, ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err == nil || job.State != JobFailed || calls.Load() != 0 {
		t.Fatalf("job=%#v calls=%d err=%v", job, calls.Load(), err)
	}
}
