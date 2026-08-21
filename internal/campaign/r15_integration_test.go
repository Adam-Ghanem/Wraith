package campaign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentbuiltin"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentexec"
	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func TestR15CampaignCycleDelegatesAuthorizedLocalhostWorkToBuiltInOwners(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path == "/.well-known/security.txt" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "alpha", Target: server.URL, ScopeVersion: "scope-v1", Authorized: true, Profile: assessment.ProfileSafe, ExpiresAt: now.Add(time.Minute), Limits: assessment.Limits{MaxRequests: 16, MaxConcurrency: 1, MaxRate: 20, MaxDuration: time.Minute}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	campaignState, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "surface-1", ProjectID: "alpha", Fingerprint: "fingerprint-1", SourceVersion: "r11.6-v1"}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := campaignState.NewCycle(CycleInput{CreatedAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	transport := httpengine.NewEngine(httpengine.Config{Gateway: r15AllowGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}, RequestTimeout: time.Second, MaxConcurrentRequests: 1, MaxResponseBytes: 1 << 20})
	defer func() { _ = transport.CloseIdleConnections() }()
	source := r15InventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: server.URL}}}
	outboundRegistry, err := outbound.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assessmentbuiltin.NewRegistry(assessmentbuiltin.Dependencies{Client: transport, Outbound: &outbound.Gateway{Registry: outboundRegistry, Targets: r15AllowGateway{}, Audit: &r15AuditStore{}, Now: time.Now}, EndpointSource: source})
	if err != nil {
		t.Fatal(err)
	}
	limits := pentest.DefaultLimits()
	limits.MaxRequests, limits.MaxDuration, limits.MaxConcurrency, limits.MaxRate = 16, time.Minute, 1, 20
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(limits.MaxRate)
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(limits.MaxConcurrency)
	if err != nil {
		t.Fatal(err)
	}
	parsedTarget, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	authorityVersion, err := scope.NewVersion(scope.VersionInput{ProjectID: "alpha", Version: "scope-v1", CreatedAt: now, Rules: []scope.Rule{{Kind: scope.RuleScheme, Effect: scope.EffectAllow, Value: parsedTarget.Scheme}, {Kind: scope.RuleIPExact, Effect: scope.EffectAllow, Value: parsedTarget.Hostname()}, {Kind: scope.RulePort, Effect: scope.EffectAllow, Value: parsedTarget.Port()}}})
	if err != nil {
		t.Fatal(err)
	}
	authorizationRecord, err := authorization.Create(authorization.CreateInput{ProjectID: "alpha", Subject: "owner-a", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	trustFactory := func(_ context.Context, snapshot assessment.ScopeSnapshot, task assessment.Task, campaignID string) (trustcontext.Context, error) {
		decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: authorizationRecord, Scope: authorityVersion, ProjectID: snapshot.ProjectID, Target: snapshot.Target, TaskID: task.ID, AssessmentID: task.AssessmentID, BudgetAvailable: true, Now: now})
		if err != nil {
			return trustcontext.Context{}, err
		}
		return trustcontext.New(trustcontext.Input{Decision: decision, Record: authorizationRecord, Scope: authorityVersion, TaskID: task.ID, AssessmentID: task.AssessmentID, CampaignID: campaignID, BudgetReference: "campaign-budget", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	}
	engine := assessmentexec.NewEngine(&registry, assessmentexec.Dependencies{RunContext: pentest.RunContext{Budget: budget, Rate: rate, Concurrency: concurrency}, Now: time.Now, Authorize: func(context.Context, assessment.ScopeSnapshot) error { return nil }, ValidateTask: func(context.Context, assessment.ScopeSnapshot, assessment.Task) error { return nil }, TrustContext: trustFactory, AuditTrust: func(context.Context, trustcontext.Context) error { return nil }})
	coordinator := Coordinator{Authorize: func(context.Context, assessment.ScopeSnapshot) error { return nil }, Execute: engine.Execute, Now: time.Now}

	summary, err := coordinator.Run(context.Background(), RunRequest{Campaign: &campaignState, Cycle: &cycle, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 || summary.Tasks[0].Owner != assessmentbuiltin.OwnerCrawler || summary.Tasks[0].Status != assessmentexec.StatusCompleted || summary.Tasks[1].Owner != assessmentbuiltin.OwnerEndpoints || summary.Tasks[1].Status != assessmentexec.StatusCompleted {
		t.Fatalf("calls=%d summary=%#v", calls.Load(), summary)
	}
	if summary.Status != assessmentexec.StatusPartial || campaignState.Status != StatusPaused || cycle.Status != StatusPaused {
		t.Fatalf("summary=%#v campaign=%#v cycle=%#v, want truthful partial/paused lifecycle", summary, campaignState, cycle)
	}
}

type r15AllowGateway struct{}

func (r15AllowGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action}, nil
}

type r15AuditStore struct{ sequence int64 }

func (store *r15AuditStore) AppendAuthorizationLifecycleEvent(_ context.Context, input securitytrust.AuditEventInput) (securitytrust.AuditEvent, error) {
	store.sequence++
	input.Sequence = store.sequence
	return securitytrust.NewAuditEvent(input)
}

type r15InventorySource struct{ endpoints []evidence.Endpoint }

func (source r15InventorySource) ListEndpoints(context.Context, string) ([]evidence.Endpoint, error) {
	return append([]evidence.Endpoint(nil), source.endpoints...), nil
}
func (r15InventorySource) ListParameters(context.Context, string) ([]evidence.Parameter, error) {
	return nil, nil
}
func (r15InventorySource) ListWebAssets(context.Context, string) ([]evidence.WebAsset, error) {
	return nil, nil
}

var _ endpointintelligence.Source = r15InventorySource{}
var _ httpengine.Resolver = r15LoopbackResolver{}

type r15LoopbackResolver struct{}

func (r15LoopbackResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
