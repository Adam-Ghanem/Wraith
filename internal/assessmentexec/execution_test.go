package assessmentexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

func TestEngineCompletesTasksInDependencyOrderAndEmitsSecretFreeEvents(t *testing.T) {
	plan := testPlan(t)
	calls := []assessment.TaskType{}
	registry := testRegistry(t, func(task assessment.Task) error {
		calls = append(calls, task.Type)
		return nil
	})
	engine := NewEngine(registry, testDependencies(t))

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if summary.Status != StatusCompleted || len(summary.Tasks) != 2 {
		t.Fatalf("summary = %#v, want completed two-task assessment", summary)
	}
	if len(calls) != 2 || calls[0] != assessment.TaskCrawl || calls[1] != assessment.TaskEndpoints {
		t.Fatalf("adapter calls = %v, want crawl then endpoint inventory", calls)
	}
	if got := summary.Tasks[1].Status; got != StatusCompleted {
		t.Fatalf("endpoint task status = %q, want %q", got, StatusCompleted)
	}
	if got := eventTypes(summary.Events); !containsEventSequence(got, []string{"assessment.started", "assessment.validated", "task.queued", "task.started", "task.completed", "assessment.completed"}) {
		t.Fatalf("event types = %v, want lifecycle event sequence", got)
	}
	for _, event := range summary.Events {
		if event.ProjectID != plan.Scope.ProjectID {
			t.Fatalf("event project = %q, want %q", event.ProjectID, plan.Scope.ProjectID)
		}
		if containsSecretLike(event.Reason) {
			t.Fatalf("event reason leaked secret-like value: %#v", event)
		}
	}
}

func TestEngineRejectsCyclicPlanBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Tasks[0].Dependencies = []string{plan.Tasks[1].ID}
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil {
		t.Fatal("Execute() error = nil, want cycle rejection")
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero for malformed plan", calls)
	}
}

func TestEngineRejectsUnauthorizedPlanBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Scope.Authorized = false
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil {
		t.Fatal("Execute() error = nil, want authorization rejection")
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero without authorization", calls)
	}
}

func TestEngineRejectsSecretLikeTaskContextBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Scope.Target = "https://example.test/?token=secret-value"
	plan.Tasks[0].Target = plan.Scope.Target
	plan.Tasks[1].Target = plan.Scope.Target
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil {
		t.Fatal("Execute() error = nil, want secret-like context rejection")
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero for secret-like task context", calls)
	}
}

func TestEngineRejectsRawQueryValuesBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Scope.Target = "https://example.test/?parameter=opaque-value"
	for index := range plan.Tasks {
		plan.Tasks[index].Target = plan.Scope.Target
	}
	calls := 0
	engine := NewEngine(testRegistry(t, func(assessment.Task) error { calls++; return nil }), testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil || calls != 0 {
		t.Fatalf("raw query value reached execution: calls=%d err=%v", calls, err)
	}
}

func TestEngineRejectsUnknownProfileBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Scope.Profile = assessment.Profile("unapproved")
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil {
		t.Fatal("Execute() error = nil, want unknown profile rejection")
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero for invalid profile", calls)
	}
}

func TestEngineRejectsEmptyTargetBeforeAdapterInvocation(t *testing.T) {
	plan := testPlan(t)
	plan.Scope.Target = ""
	for index := range plan.Tasks {
		plan.Tasks[index].Target = ""
	}
	calls := 0
	engine := NewEngine(testRegistry(t, func(assessment.Task) error { calls++; return nil }), testDependencies(t))

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil || calls != 0 {
		t.Fatalf("empty target reached execution: calls=%d err=%v", calls, err)
	}
}

func TestEngineRejectsSecretLikeAdapterEvidenceReferences(t *testing.T) {
	plan := testPlan(t)
	plan.Tasks = plan.Tasks[:1]
	configured, err := assessment.NewAdapterRegistry(assessment.TypedAdapter{TaskType: assessment.TaskCrawl, Adapter: sensitiveResultAdapter{owner: "test.crawl"}})
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(&configured, testDependencies(t))

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if summary.Tasks[0].Status != StatusFailed || len(summary.Tasks[0].Result.EvidenceRefs) != 0 {
		t.Fatalf("summary = %#v, want failed task with no leaked evidence reference", summary)
	}
}

func TestEngineStopsBeforeAdapterWhenInjectedR1AuthorizationRecheckFails(t *testing.T) {
	plan := testPlan(t)
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, Dependencies{
		RunContext: testRunContext(t),
		Now:        fixedNow,
		Authorize: func(context.Context, assessment.ScopeSnapshot) error {
			return errors.New("authorization expired")
		},
	})

	if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil {
		t.Fatal("Execute() error = nil, want injected authorization failure")
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero after denied recheck", calls)
	}
}

func TestEngineRechecksAuthorizationImmediatelyBeforeAdapterDispatch(t *testing.T) {
	plan := testPlan(t)
	plan.Tasks = plan.Tasks[:1]
	calls := 0
	checks := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	deps := testDependencies(t)
	deps.Authorize = func(context.Context, assessment.ScopeSnapshot) error {
		checks++
		if checks >= 3 {
			return errors.New("authorization revoked")
		}
		return nil
	}
	engine := NewEngine(registry, deps)

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if calls != 0 || summary.Tasks[0].Status != StatusCancelled || summary.Tasks[0].Reason != "authorization_expired" {
		t.Fatalf("summary = %#v calls=%d, want no adapter dispatch after authorization revocation", summary, calls)
	}
}

func TestEngineBlocksWorkWhenSharedTaskBudgetIsExhausted(t *testing.T) {
	plan := testPlan(t)
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	deps := testDependencies(t)
	deps.RunContext = testRunContextWithRequests(t, 1)
	engine := NewEngine(registry, deps)

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if calls != 1 || summary.Tasks[0].Status != StatusCompleted || summary.Tasks[1].Status != StatusBlocked || summary.Tasks[1].Reason != "budget_exhausted" {
		t.Fatalf("summary = %#v calls=%d, want one completion and one budget block", summary, calls)
	}
}

func TestEngineDryRunNeverInvokesAdapter(t *testing.T) {
	plan := testPlan(t)
	calls := 0
	registry := testRegistry(t, func(assessment.Task) error { calls++; return nil })
	engine := NewEngine(registry, testDependencies(t))

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID, DryRun: true})
	if err != nil {
		t.Fatalf("dry-run Execute() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("adapter calls = %d, want zero in dry run", calls)
	}
	if summary.Status != StatusCompleted || summary.Tasks[0].Status != StatusSkipped {
		t.Fatalf("dry-run summary = %#v, want completed/skipped", summary)
	}
}

func TestEngineBlocksDependentTaskAfterFailure(t *testing.T) {
	plan := testPlan(t)
	registry := testRegistry(t, func(task assessment.Task) error {
		if task.Type == assessment.TaskCrawl {
			return errors.New("owner failed")
		}
		return nil
	})
	engine := NewEngine(registry, testDependencies(t))

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if summary.Status != StatusPartial || summary.Tasks[0].Status != StatusFailed || summary.Tasks[1].Status != StatusBlocked {
		t.Fatalf("summary = %#v, want failed parent and blocked dependent", summary)
	}
}

func TestTaskExecutionRejectsInvalidTerminalTransition(t *testing.T) {
	task := TaskExecution{TaskID: "task-1", Status: StatusCompleted}
	if err := task.Transition(StatusRunning, fixedNow()); err == nil {
		t.Fatal("Transition() error = nil, want terminal-state rejection")
	}
}

func TestEngineMarksQueuedTasksCancelledWhenContextIsCancelled(t *testing.T) {
	plan := testPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	registry := testRegistry(t, func(assessment.Task) error { t.Fatal("adapter must not run after cancellation"); return nil })
	engine := NewEngine(registry, testDependencies(t))

	summary, err := engine.Execute(ctx, ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if summary.Status != StatusCancelled || summary.Tasks[0].Status != StatusCancelled || summary.Tasks[1].Status != StatusCancelled {
		t.Fatalf("summary = %#v, want deterministic cancellation", summary)
	}
}

func TestEngineCancelsAdapterWhenPerTaskDeadlineExpires(t *testing.T) {
	plan := testPlan(t)
	plan.Tasks = plan.Tasks[:1]
	configured, err := assessment.NewAdapterRegistry(assessment.TypedAdapter{TaskType: assessment.TaskCrawl, Adapter: blockingAdapter{owner: "test.crawl"}})
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(&configured, testDependencies(t))

	summary, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID, TaskTimeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if summary.Status != StatusCancelled || summary.Tasks[0].Status != StatusCancelled || summary.Tasks[0].Reason != "cancelled" {
		t.Fatalf("summary = %#v, want cancelled timed-out task", summary)
	}
}

func testPlan(t *testing.T) assessment.AssessmentPlan {
	t.Helper()
	now := fixedNow()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "project-a", Target: "https://example.test", ScopeVersion: "scope-v1", Authorized: true, Profile: assessment.ProfileSafe, ExpiresAt: time.Now().UTC().Add(time.Hour), Limits: assessment.Limits{MaxRequests: 32, MaxConcurrency: 2, MaxRate: 10, MaxDuration: time.Minute}, CreatedAt: now})
	if err != nil {
		t.Fatalf("PlanActiveAssessment() error = %v", err)
	}
	plan.Tasks = plan.Tasks[:2]
	return plan
}

func testRegistry(t *testing.T, run func(assessment.Task) error) *assessment.AdapterRegistry {
	t.Helper()
	bindings := []assessment.TypedAdapter{
		{TaskType: assessment.TaskCrawl, Adapter: adapterFunc{owner: "test.crawl", run: run}},
		{TaskType: assessment.TaskEndpoints, Adapter: adapterFunc{owner: "test.endpoints", run: run}},
	}
	registry, err := assessment.NewAdapterRegistry(bindings...)
	if err != nil {
		t.Fatalf("NewAdapterRegistry() error = %v", err)
	}
	return &registry
}

type adapterFunc struct {
	owner string
	run   func(assessment.Task) error
}

func (adapter adapterFunc) Owner() string { return adapter.owner }
func (adapter adapterFunc) Execute(_ context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
	if err := adapter.run(taskContext.Task); err != nil {
		return assessment.AdapterResult{}, err
	}
	return assessment.AdapterResult{Owner: adapter.owner, TaskID: taskContext.Task.ID}, nil
}

type blockingAdapter struct{ owner string }

func (adapter blockingAdapter) Owner() string { return adapter.owner }
func (blockingAdapter) Execute(ctx context.Context, _ assessment.TaskContext) (assessment.AdapterResult, error) {
	<-ctx.Done()
	return assessment.AdapterResult{}, ctx.Err()
}

type sensitiveResultAdapter struct{ owner string }

func (adapter sensitiveResultAdapter) Owner() string { return adapter.owner }
func (adapter sensitiveResultAdapter) Execute(_ context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
	return assessment.AdapterResult{Owner: adapter.owner, TaskID: taskContext.Task.ID, EvidenceRefs: []string{"token=secret-value"}}, nil
}

func testRunContext(t *testing.T) pentest.RunContext {
	return testRunContextWithRequests(t, pentest.DefaultLimits().MaxRequests)
}

func testDependencies(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		RunContext: testRunContext(t),
		Now:        fixedNow,
		Authorize:  func(context.Context, assessment.ScopeSnapshot) error { return nil },
	}
}

func testRunContextWithRequests(t *testing.T, maxRequests int) pentest.RunContext {
	t.Helper()
	limits := pentest.DefaultLimits()
	limits.MaxRequests = maxRequests
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(limits.MaxConcurrency)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(limits.MaxRate)
	if err != nil {
		t.Fatal(err)
	}
	return pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}
}

func eventTypes(events []ExecutionEvent) []string {
	values := make([]string, len(events))
	for index, event := range events {
		values[index] = event.Type
	}
	return values
}

func containsEventSequence(values, wanted []string) bool {
	next := 0
	for _, value := range values {
		if next < len(wanted) && value == wanted[next] {
			next++
		}
	}
	return next == len(wanted)
}

func fixedNow() time.Time { return time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC) }
