package assessment

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

type recordingAdapter struct {
	owner string
	calls []TaskContext
}

func (a *recordingAdapter) Owner() string { return a.owner }
func (a *recordingAdapter) Execute(_ context.Context, task TaskContext) (AdapterResult, error) {
	a.calls = append(a.calls, task)
	return AdapterResult{Owner: a.owner, TaskID: task.Task.ID}, nil
}

func TestAdapterRegistryMapsEachTaskToOneOwnerAndDelegates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	plan, err := PlanActiveAssessment(PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "scope-v1", Profile: ProfileSafe, ExpiresAt: now.Add(time.Hour), Limits: Limits{MaxRequests: 8, MaxDuration: time.Minute, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	adapters := make([]TypedAdapter, 0, len(plan.Tasks))
	records := map[TaskType]*recordingAdapter{}
	for _, task := range plan.Tasks {
		adapter := &recordingAdapter{owner: "owner-" + string(task.Type)}
		records[task.Type] = adapter
		adapters = append(adapters, TypedAdapter{TaskType: task.Type, Adapter: adapter})
	}
	registry, err := NewAdapterRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdapterRegistry(adapters[0], adapters[0]); err == nil {
		t.Fatal("expected duplicate task owner rejection")
	}
	budget, err := pentest.NewBudgetManager(pentest.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(1)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := registry.Execute(context.Background(), plan, pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Completed) != len(plan.Tasks) {
		t.Fatalf("result=%#v", result)
	}
	for kind, adapter := range records {
		if len(adapter.calls) != 1 || adapter.calls[0].Task.Type != kind || adapter.calls[0].Scope.ProjectID != "alpha" || adapter.calls[0].Scope.Authorized != true {
			t.Fatalf("kind=%s calls=%#v", kind, adapter.calls)
		}
	}
	if _, err := NewAdapterRegistry(TypedAdapter{TaskType: TaskCrawl, Adapter: &recordingAdapter{owner: ""}}); err == nil {
		t.Fatal("expected blank owner rejection")
	}
}

func TestAdapterRegistryDispatchRejectsExpiredScopeBeforeOwnerInvocation(t *testing.T) {
	adapter := &recordingAdapter{owner: "owner-crawl"}
	registry, err := NewAdapterRegistry(TypedAdapter{TaskType: TaskCrawl, Adapter: adapter})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := pentest.NewBudgetManager(pentest.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(1)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	task := Task{ID: "task-crawl", AssessmentID: "assessment-a", ProjectID: "project-a", Type: TaskCrawl, Target: "https://app.test"}
	_, err = registry.Dispatch(context.Background(), TaskContext{AssessmentID: task.AssessmentID, Scope: ScopeSnapshot{ProjectID: task.ProjectID, Target: task.Target, Authorized: true, ExpiresAt: time.Now().Add(-time.Second)}, Task: task, RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}})
	if err == nil {
		t.Fatal("Dispatch() error = nil, want expired-scope rejection")
	}
	if len(adapter.calls) != 0 {
		t.Fatalf("adapter calls = %d, want zero after scope expiry", len(adapter.calls))
	}
}

func TestAdapterRegistryDispatchRejectsInvalidScopeLimitsBeforeOwnerInvocation(t *testing.T) {
	adapter := &recordingAdapter{owner: "owner-crawl"}
	registry, err := NewAdapterRegistry(TypedAdapter{TaskType: TaskCrawl, Adapter: adapter})
	if err != nil {
		t.Fatal(err)
	}
	limits := pentest.DefaultLimits()
	budget, err := pentest.NewBudgetManager(limits)
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(1)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	task := Task{ID: "task-crawl", AssessmentID: "assessment-a", ProjectID: "project-a", Type: TaskCrawl, Target: "https://app.test"}
	_, err = registry.Dispatch(context.Background(), TaskContext{AssessmentID: task.AssessmentID, Scope: ScopeSnapshot{ProjectID: task.ProjectID, Target: task.Target, Authorized: true, ExpiresAt: now.Add(time.Minute), Limits: Limits{MaxRequests: 0, MaxConcurrency: 1, MaxRate: 1, MaxDuration: time.Minute}}, Task: task, RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: func() time.Time { return now }})
	if err == nil {
		t.Fatal("Dispatch() error = nil, want invalid-limit rejection")
	}
	if len(adapter.calls) != 0 {
		t.Fatalf("adapter calls = %d, want zero after invalid-limit rejection", len(adapter.calls))
	}
}
