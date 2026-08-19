package assessment

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

func TestPlanActiveAssessmentIsDeterministicProjectScopedAndBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	input := PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "scope-v1", Profile: ProfileStandard, ExpiresAt: now.Add(time.Hour), Limits: Limits{MaxRequests: 32, MaxDuration: time.Minute, MaxConcurrency: 2, MaxRate: 5}, CreatedAt: now}
	first, err := PlanActiveAssessment(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanActiveAssessment(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.AssessmentID != second.AssessmentID || len(first.Tasks) == 0 || first.Tasks[0].ProjectID != "alpha" {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	for _, task := range first.Tasks {
		if task.ProjectID != "alpha" || task.AssessmentID != first.AssessmentID || task.ID == "" {
			t.Fatalf("task=%#v", task)
		}
	}
	if !containsTask(first.Tasks, TaskInjection) || !containsTask(first.Tasks, TaskFuzz) || !containsTask(first.Tasks, TaskValidation) {
		t.Fatalf("tasks=%#v", first.Tasks)
	}
	if _, err := PlanActiveAssessment(PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "scope-v1", Profile: ProfileSafe, ExpiresAt: now.Add(-time.Second), Limits: input.Limits, CreatedAt: now}); err == nil {
		t.Fatal("expected expired scope rejection")
	}
	if _, err := PlanActiveAssessment(PlanInput{ProjectID: "alpha", Target: "https://app.test", ScopeVersion: "scope-v1", Profile: ProfileStandard, ExpiresAt: now.Add(time.Hour), Limits: input.Limits, CreatedAt: now}); err == nil {
		t.Fatal("expected authorization rejection")
	}
}

func TestPlanActiveAssessmentProfilesAndDependenciesFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	limits := Limits{MaxRequests: 32, MaxDuration: time.Minute, MaxConcurrency: 2, MaxRate: 5}
	safe, err := PlanActiveAssessment(PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "v1", Profile: ProfileSafe, ExpiresAt: now.Add(time.Hour), Limits: limits, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if containsTask(safe.Tasks, TaskInjection) || containsTask(safe.Tasks, TaskFuzz) {
		t.Fatalf("safe tasks=%#v", safe.Tasks)
	}
	if err := ValidateTasks(safe.Tasks); err != nil {
		t.Fatal(err)
	}
	broken := append([]Task(nil), safe.Tasks...)
	broken[0].Dependencies = []string{"missing"}
	if err := ValidateTasks(broken); err == nil {
		t.Fatal("expected invalid dependency rejection")
	}
}

func TestExecuteRequiresSharedControlsAndRechecksScope(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	plan, err := PlanActiveAssessment(PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "v1", Profile: ProfileSafe, ExpiresAt: now.Add(time.Hour), Limits: Limits{MaxRequests: 32, MaxDuration: time.Minute, MaxConcurrency: 2, MaxRate: 5}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), plan, ExecutionDependencies{}); err == nil {
		t.Fatal("expected missing shared controls rejection")
	}
	budget, err := pentest.NewBudgetManager(pentest.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(2)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(5)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	result, err := Execute(context.Background(), plan, ExecutionDependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: func() time.Time { return now }, RunTask: func(_ context.Context, task Task, _ pentest.RunContext) error {
		called++
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if called != len(plan.Tasks) || len(result.Completed) != len(plan.Tasks) || len(result.Failed) != 0 {
		t.Fatalf("result=%#v called=%d", result, called)
	}
	expired := plan
	expired.Scope.ExpiresAt = now.Add(-time.Second)
	if _, err := Execute(context.Background(), expired, ExecutionDependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("expected execution scope expiry rejection")
	}
}

func containsTask(tasks []Task, kind TaskType) bool {
	for _, task := range tasks {
		if task.Type == kind {
			return true
		}
	}
	return false
}
