// Package assessmentbuiltin binds only existing owner-owned Wraith capabilities
// to R13.1. It creates no transport, policy, limiter, scanner, or evidence model.
package assessmentbuiltin

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/crawler"
	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/smartdiscovery"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

const (
	OwnerCrawler   = "r4.crawler"
	OwnerEndpoints = "r5.endpoint_inventory"
	OwnerDiscovery = "r11.2.smart_discovery"
)

type Dependencies struct {
	Client httpengine.Client
	Outbound          *outbound.Gateway
	Repository        evidence.Repository
	EndpointSource    endpointintelligence.Source
	DiscoveryEvidence smartdiscovery.DiscoveryEvidenceSink
	ScopeStore interface {
		LoadScopeVersion(context.Context, string, string) (scope.Version, error)
		LoadActiveAuthorizationForScope(context.Context, string, string, time.Time) (authorization.Record, error)
	}
	Now func() time.Time
}

type adapter struct {
	owner           string
	requestControls bool
	execute         func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error)
}

func (adapter adapter) Owner() string             { return adapter.owner }
func (adapter adapter) OwnsRequestControls() bool { return adapter.requestControls }
func (adapter adapter) Execute(ctx context.Context, task assessment.TaskContext) (assessment.AdapterResult, error) {
	if adapter.execute == nil {
		return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(adapter.owner)
	}
	return adapter.execute(ctx, task)
}

func NewRegistry(dependencies Dependencies) (assessment.AdapterRegistry, error) {
	values := []assessment.TypedAdapter{
		{TaskType: assessment.TaskCrawl, Adapter: adapter{owner: OwnerCrawler, requestControls: true, execute: crawlAdapter(dependencies)}},
		{TaskType: assessment.TaskEndpoints, Adapter: adapter{owner: OwnerEndpoints, execute: endpointAdapter(dependencies)}},
		{TaskType: assessment.TaskDiscovery, Adapter: adapter{owner: OwnerDiscovery, requestControls: true, execute: discoveryAdapter(dependencies)}},
		{TaskType: assessment.TaskNetworkPortDiscovery, Adapter: adapter{owner: OwnerNetworkPortDiscovery, execute: npdAdapter(dependencies)}},
	}
	for _, taskType := range []assessment.TaskType{assessment.TaskJS, assessment.TaskBaseline, assessment.TaskMutation, assessment.TaskFuzz, assessment.TaskInjection, assessment.TaskValidation, assessment.TaskCorrelation, assessment.TaskFinding, assessment.TaskRisk, assessment.TaskSurface, assessment.TaskReport} {
		values = append(values, assessment.TypedAdapter{TaskType: taskType, Adapter: adapter{owner: "unavailable." + string(taskType)}})
	}
	return assessment.NewAdapterRegistry(values...)
}

func crawlAdapter(dependencies Dependencies) func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return func(ctx context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
		if dependencies.Client == nil || dependencies.Outbound == nil || !validTask(taskContext, assessment.TaskCrawl) {
			return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(OwnerCrawler)
		}
		config := crawler.DefaultConfig(taskContext.Scope.ProjectID, taskContext.Scope.Target)
		config.MaxDepth = 0
		config.MaxPages = 1
		config.MaxConcurrency = 1
		config.MaxQueryVariants = 1
		config.MaxResponseBytes = 1 << 20
		config.MaxTotalBytes = config.MaxResponseBytes
		config.Timeout = boundedTimeout(taskContext.Scope.Limits.MaxDuration)
		config.MaxDuration = boundedDuration(taskContext.Scope.Limits.MaxDuration)
		config.MaxRedirects = 0
		config.RespectRobots = false
		client := &controlledClient{client: dependencies.Client, outbound: dependencies.Outbound, capabilityID: "assessment-crawl-read", trust: taskContext.Trust, runContext: taskContext.RunContext, manageControls: true, now: taskContext.Now}
		result, err := (crawler.Crawler{Client: client, Repository: dependencies.Repository}).Crawl(ctx, config)
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		if err := client.Err(); err != nil {
			return assessment.AdapterResult{}, err
		}
		if len(result.Errors) > 0 {
			return assessment.AdapterResult{}, errors.New("crawl adapter did not complete all bounded delegated requests")
		}
		return assessment.AdapterResult{Owner: OwnerCrawler, TaskID: taskContext.Task.ID, SignalCount: result.PagesFetched}, nil
	}
}

func endpointAdapter(dependencies Dependencies) func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return func(ctx context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
		if dependencies.EndpointSource == nil || !validTask(taskContext, assessment.TaskEndpoints) {
			return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(OwnerEndpoints)
		}
		inventory, err := endpointintelligence.Build(ctx, dependencies.EndpointSource, taskContext.Scope.ProjectID, endpointintelligence.DefaultLimits())
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		references := make([]string, 0, len(inventory.Endpoints))
		for _, endpoint := range inventory.Endpoints {
			if endpoint.Identity == "" || endpoint.URL == "" {
				return assessment.AdapterResult{}, errors.New("endpoint inventory contains invalid identity")
			}
			references = append(references, endpoint.Identity)
		}
		sort.Strings(references)
		return assessment.AdapterResult{Owner: OwnerEndpoints, TaskID: taskContext.Task.ID, EvidenceRefs: references, SignalCount: inventory.EndpointCount}, nil
	}
}

func discoveryAdapter(dependencies Dependencies) func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return func(ctx context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
		if dependencies.Client == nil || dependencies.Outbound == nil || dependencies.EndpointSource == nil || !validTask(taskContext, assessment.TaskDiscovery) {
			return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(OwnerDiscovery)
		}
		inventory, err := endpointintelligence.Build(ctx, dependencies.EndpointSource, taskContext.Scope.ProjectID, endpointintelligence.DefaultLimits())
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		limits := smartdiscovery.DefaultLimits()
		if taskContext.Scope.Limits.MaxRequests < limits.MaxCandidates {
			limits.MaxCandidates = taskContext.Scope.Limits.MaxRequests
		}
		plan, err := smartdiscovery.Build(smartdiscovery.Input{ProjectID: taskContext.Scope.ProjectID, RunID: taskContext.AssessmentID, BaseURL: taskContext.Scope.Target, Inventory: inventory, Limits: limits})
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		client := &controlledClient{client: dependencies.Client, outbound: dependencies.Outbound, capabilityID: "assessment-discovery-read", trust: taskContext.Trust, runContext: taskContext.RunContext, now: taskContext.Now}
		run, err := smartdiscovery.Verify(ctx, verifiableCandidates(plan.Candidates), smartdiscovery.VerificationDependencies{Client: client, Budget: taskContext.RunContext.Budget, Rate: taskContext.RunContext.Rate, Concurrency: taskContext.RunContext.Concurrency, Evidence: dependencies.DiscoveryEvidence}, smartdiscovery.VerificationOptions{Authorized: true, Verify: true, MaxDuration: boundedDuration(taskContext.Scope.Limits.MaxDuration), MaxResponseBytes: 1 << 20})
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		return assessment.AdapterResult{Owner: OwnerDiscovery, TaskID: taskContext.Task.ID, SignalCount: run.RequestsSent}, nil
	}
}

func verifiableCandidates(values []smartdiscovery.DiscoveryCandidate) []smartdiscovery.DiscoveryCandidate {
	result := make([]smartdiscovery.DiscoveryCandidate, 0, len(values))
	for _, candidate := range values {
		switch candidate.Type {
		case smartdiscovery.CandidateEndpoint, smartdiscovery.CandidatePath, smartdiscovery.CandidateAPIRoute, smartdiscovery.CandidateAPIVersion, smartdiscovery.CandidateStaticResource, smartdiscovery.CandidateDocumentation, smartdiscovery.CandidateBackupLikeResource, smartdiscovery.CandidateConfigurationLikeResource:
			result = append(result, candidate)
		}
	}
	return result
}

func validTask(taskContext assessment.TaskContext, taskType assessment.TaskType) bool {
	return taskContext.Task.Type == taskType && strings.TrimSpace(taskContext.Task.ID) != "" && taskContext.Task.ProjectID == taskContext.Scope.ProjectID && taskContext.Task.Target == taskContext.Scope.Target && taskContext.Scope.Authorized
}

func boundedTimeout(limit time.Duration) time.Duration {
	if limit <= 0 || limit > 30*time.Second {
		return 30 * time.Second
	}
	return limit
}

func boundedDuration(limit time.Duration) time.Duration {
	if limit <= 0 || limit > 30*time.Second {
		return 30 * time.Second
	}
	return limit
}

type controlledClient struct {
	client         httpengine.Client
	outbound       *outbound.Gateway
	capabilityID   string
	trust          trustcontext.Context
	runContext     pentest.RunContext
	manageControls bool
	now            func() time.Time
	mu             sync.Mutex
	err            error
	sequence       int
}

func (client *controlledClient) Do(ctx context.Context, request httpengine.Request) (httpengine.Response, error) {
	if client.client == nil || client.outbound == nil || client.manageControls && (client.runContext.Budget == nil || client.runContext.Rate == nil || client.runContext.Concurrency == nil) {
		return httpengine.Response{}, client.record(errors.New("shared request controls are unavailable"))
	}
	if client.manageControls {
		if err := client.runContext.Budget.Consume(pentest.BudgetUse{Requests: 1}); err != nil {
			return httpengine.Response{}, client.record(err)
		}
		if err := client.runContext.Rate.Wait(ctx); err != nil {
			return httpengine.Response{}, client.record(err)
		}
		release, err := client.runContext.Concurrency.Acquire(ctx)
		if err != nil {
			return httpengine.Response{}, client.record(err)
		}
		defer release()
	}
	now := time.Now
	if client.now != nil {
		now = client.now
	}
	client.mu.Lock()
	client.sequence++
	sequence := client.sequence
	client.mu.Unlock()
	operation := outbound.Operation{ID: "t5-" + client.trust.TaskFingerprint + "-" + strconv.Itoa(sequence), ProjectID: request.ProjectID, CapabilityID: client.capabilityID, TaskID: client.trust.TaskID, AssessmentID: client.trust.AssessmentID, CampaignID: client.trust.CampaignID, BudgetReference: client.trust.BudgetReference, Destination: request.URL, Trust: client.trust, CreatedAt: now().UTC(), ExpiresAt: client.trust.ExpiresAt.UTC()}
	response, err := (outbound.Client{Gateway: *client.outbound, Transport: client.client}).Do(ctx, operation, request)
	if err != nil {
		return httpengine.Response{}, client.record(err)
	}
	return response, nil
}

func (client *controlledClient) record(err error) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.err == nil {
		client.err = err
	}
	return err
}

func (client *controlledClient) Err() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.err
}
