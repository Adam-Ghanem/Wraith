package assessmentbuiltin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func TestRegistryDelegatesCrawlOnlyThroughInjectedR3Client(t *testing.T) {
	client := &recordingClient{response: httpengine.Response{StatusCode: 200, ContentType: "text/html", ContentLength: 23, Body: []byte("<html><body>ok</body></html>")}}
	taskContext := testTaskContext(t, assessment.TaskCrawl)
	registry, err := NewRegistry(Dependencies{Client: client, Outbound: testOutboundGateway(t, taskContext)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := registry.Dispatch(context.Background(), taskContext)
	if err != nil {
		t.Fatal(err)
	}
	if result.Owner != OwnerCrawler || result.TaskID == "" || result.SignalCount != 1 {
		t.Fatalf("result=%#v", result)
	}
	if len(client.requests) != 2 || client.requests[0].Source != "crawler" || client.requests[1].Source != "crawler.securitytxt" || client.requests[0].ProjectID != "alpha" {
		t.Fatalf("r3 requests=%#v", client.requests)
	}
}

func TestCrawlAdapterRejectsMissingT5GatewayBeforeR3Delegation(t *testing.T) {
	client := &recordingClient{response: httpengine.Response{StatusCode: 200, ContentType: "text/html", Body: []byte("<html>ok</html>")}}
	registry, err := NewRegistry(Dependencies{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Dispatch(context.Background(), testTaskContext(t, assessment.TaskCrawl))
	if err == nil {
		t.Fatal("crawl dispatch succeeded without required T5 outbound gateway")
	}
	if len(client.requests) != 0 {
		t.Fatalf("R3 requests = %#v, want zero without T5 gateway", client.requests)
	}
}

func TestCrawlAdapterChargesEveryR3RequestToSharedBudgetAndFailsPartialWork(t *testing.T) {
	client := &recordingClient{response: httpengine.Response{StatusCode: 200, ContentType: "text/html", ContentLength: 23, Body: []byte("<html><body>ok</body></html>")}}
	taskContext := testTaskContext(t, assessment.TaskCrawl)
	registry, err := NewRegistry(Dependencies{Client: client, Outbound: testOutboundGateway(t, taskContext)})
	if err != nil {
		t.Fatal(err)
	}
	limits := pentest.DefaultLimits()
	limits.MaxRequests = 1
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		t.Fatal(err)
	}
	taskContext.RunContext.Budget = budget
	if _, err := registry.Dispatch(context.Background(), taskContext); err == nil {
		t.Fatal("crawl completed after its shared task budget was exhausted")
	}
	if len(client.requests) != 1 {
		t.Fatalf("requests=%#v", client.requests)
	}
}

func TestRegistryBuildsEndpointInventoryFromProjectScopedSource(t *testing.T) {
	source := inventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: "https://app.example.test/"}}}
	registry, err := NewRegistry(Dependencies{EndpointSource: source})
	if err != nil {
		t.Fatal(err)
	}
	result, err := registry.Dispatch(context.Background(), testTaskContext(t, assessment.TaskEndpoints))
	if err != nil {
		t.Fatal(err)
	}
	if result.Owner != OwnerEndpoints || result.SignalCount != 1 || len(result.EvidenceRefs) != 1 || result.EvidenceRefs[0] != "endpoint-1" {
		t.Fatalf("result=%#v", result)
	}
}

func TestRegistryDelegatesDiscoveryCandidateThroughExistingR11Verifier(t *testing.T) {
	client := &recordingClient{response: httpengine.Response{StatusCode: 200, ContentType: "text/html", ContentLength: 2, Body: []byte("ok")}}
	source := inventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: "https://app.example.test/"}}}
	taskContext := testTaskContext(t, assessment.TaskDiscovery)
	registry, err := NewRegistry(Dependencies{Client: client, Outbound: testOutboundGateway(t, taskContext), EndpointSource: source})
	if err != nil {
		t.Fatal(err)
	}
	result, err := registry.Dispatch(context.Background(), taskContext)
	if err != nil {
		t.Fatal(err)
	}
	if result.Owner != OwnerDiscovery || result.TaskID == "" || result.SignalCount != 1 {
		t.Fatalf("result=%#v", result)
	}
	if len(client.requests) != 1 || client.requests[0].Method != "HEAD" || client.requests[0].Source != "smart-discovery.r11.2.verify" {
		t.Fatalf("r3 requests=%#v", client.requests)
	}
}

func TestUnavailableBuiltinTaskFailsClosedWithoutTransport(t *testing.T) {
	client := &recordingClient{}
	registry, err := NewRegistry(Dependencies{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Dispatch(context.Background(), testTaskContext(t, assessment.TaskInjection))
	if err == nil {
		t.Fatal("unconfigured injection owner completed")
	}
	var adapterErr *assessment.AdapterError
	if !errors.As(err, &adapterErr) || adapterErr.Code != assessment.AdapterUnavailable {
		t.Fatalf("err=%v, want typed ADAPTER_UNAVAILABLE", err)
	}
	if len(client.requests) != 0 {
		t.Fatalf("unavailable owner reached transport: %#v", client.requests)
	}
}

func TestRegistryRejectsSecretLikeTargetBeforeBuiltInOwnerInvocation(t *testing.T) {
	registry, err := NewRegistry(Dependencies{EndpointSource: inventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: "https://app.example.test/"}}}})
	if err != nil {
		t.Fatal(err)
	}
	taskContext := testTaskContext(t, assessment.TaskEndpoints)
	taskContext.Scope.Target = "https://app.example.test/?token=opaque"
	taskContext.Task.Target = taskContext.Scope.Target
	if _, err := registry.Dispatch(context.Background(), taskContext); err == nil {
		t.Fatal("credential-like target reached built-in owner")
	}
}

type recordingClient struct {
	requests []httpengine.Request
	response httpengine.Response
	err      error
}

func (client *recordingClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	return client.response, client.err
}

type inventorySource struct{ endpoints []evidence.Endpoint }

func (source inventorySource) ListEndpoints(context.Context, string) ([]evidence.Endpoint, error) {
	return append([]evidence.Endpoint(nil), source.endpoints...), nil
}
func (inventorySource) ListParameters(context.Context, string) ([]evidence.Parameter, error) {
	return nil, nil
}
func (inventorySource) ListWebAssets(context.Context, string) ([]evidence.WebAsset, error) {
	return nil, nil
}

type testTargetGateway struct{}

func (testTargetGateway) Authorize(_ context.Context, projectID string, target policy.Target, _ policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: projectID == "alpha" && target.Hostname == "app.example.test", ProjectID: projectID, Target: target}, nil
}

type testAuditStore struct{ sequence int64 }

func (store *testAuditStore) AppendAuthorizationLifecycleEvent(_ context.Context, input securitytrust.AuditEventInput) (securitytrust.AuditEvent, error) {
	store.sequence++
	input.Sequence = store.sequence
	return securitytrust.NewAuditEvent(input)
}

func testOutboundGateway(t testing.TB, task assessment.TaskContext) *outbound.Gateway {
	t.Helper()
	registry, err := outbound.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return &outbound.Gateway{Registry: registry, Targets: testTargetGateway{}, Audit: &testAuditStore{}, Now: task.Now}
}

func testTaskContext(t testing.TB, taskType assessment.TaskType) assessment.TaskContext {
	t.Helper()
	limits := pentest.DefaultLimits()
	limits.MaxRequests = 8
	limits.MaxDuration = time.Minute
	limits.MaxConcurrency = 1
	limits.MaxRate = 20
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(20)
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	task := assessment.Task{ID: "task-" + string(taskType), AssessmentID: "assessment-1", ProjectID: "alpha", Type: taskType, Target: "https://app.example.test/", Status: assessment.StatusPlanned, CreatedAt: now}
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "alpha", Subject: "owner-a", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "alpha", Version: "scope-v1", CreatedAt: now.Add(-time.Minute), Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "app.example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: record, Scope: version, ProjectID: task.ProjectID, Target: task.Target, TaskID: task.ID, AssessmentID: task.AssessmentID, BudgetAvailable: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := trustcontext.New(trustcontext.Input{Decision: decision, Record: record, Scope: version, TaskID: task.ID, AssessmentID: task.AssessmentID, BudgetReference: "test-budget", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return assessment.TaskContext{AssessmentID: task.AssessmentID, Scope: assessment.ScopeSnapshot{ProjectID: "alpha", ScopeVersion: "scope-v1", Target: task.Target, Authorized: true, ExpiresAt: now.Add(time.Minute), Profile: assessment.ProfileSafe, Limits: assessment.Limits{MaxRequests: 8, MaxConcurrency: 1, MaxRate: 20, MaxDuration: time.Minute}}, Task: task, Trust: trusted, RunContext: pentest.RunContext{Budget: budget, Rate: rate, Concurrency: concurrency}, Now: func() time.Time { return now }}
}
