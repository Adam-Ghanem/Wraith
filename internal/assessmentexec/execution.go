// Package assessmentexec coordinates an already validated assessment plan.
// It intentionally owns no transport, authorization evaluator, scanner, or
// evidence/finding persistence implementation.
package assessmentexec

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

var errAuthorizationExpired = errors.New("assessment authorization expired")

type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	StatusSkipped   Status = "skipped"
	StatusBlocked   Status = "blocked"
	StatusPartial   Status = "partial"
)

type TaskExecution struct {
	TaskID, Owner, Reason string
	Status                Status
	StartedAt, FinishedAt time.Time
	Result                assessment.AdapterResult
}

func (execution *TaskExecution) Transition(next Status, now time.Time) error {
	if execution == nil || !allowedTransition(execution.Status, next) {
		return errors.New("invalid assessment execution transition")
	}
	execution.Status = next
	if next == StatusRunning {
		execution.StartedAt = now.UTC()
	}
	if terminal(next) {
		execution.FinishedAt = now.UTC()
	}
	return nil
}

type ExecutionEvent struct {
	Type, ProjectID, AssessmentID, TaskID, Reason string
	Status                                        Status
	CreatedAt                                     time.Time
}

type ExecutionSummary struct {
	AssessmentID string
	ProjectID    string
	Status       Status
	Tasks        []TaskExecution
	Events       []ExecutionEvent
}

type ExecutionRequest struct {
	Plan        assessment.AssessmentPlan
	ProjectID   string
	DryRun      bool
	MaxTasks    int
	TaskTimeout time.Duration
}

type Dependencies struct {
	RunContext pentest.RunContext
	Now        func() time.Time
	Authorize  func(context.Context, assessment.ScopeSnapshot) error
}

type Engine struct {
	registry *assessment.AdapterRegistry
	deps     Dependencies
}

func NewEngine(registry *assessment.AdapterRegistry, dependencies Dependencies) Engine {
	return Engine{registry: registry, deps: dependencies}
}

func (engine Engine) Execute(ctx context.Context, request ExecutionRequest) (ExecutionSummary, error) {
	if err := engine.validate(request); err != nil {
		return ExecutionSummary{}, err
	}
	if ctx == nil {
		return ExecutionSummary{}, errors.New("assessment execution context is required")
	}
	if err := engine.deps.Authorize(ctx, request.Plan.Scope); err != nil {
		return ExecutionSummary{}, errors.New("assessment authorization recheck failed")
	}
	now := engine.deps.Now
	summary := ExecutionSummary{AssessmentID: request.Plan.AssessmentID, ProjectID: request.Plan.Scope.ProjectID, Tasks: make([]TaskExecution, len(request.Plan.Tasks))}
	summary.emit(now, "assessment.started", "", StatusPending, "")
	summary.emit(now, "assessment.validated", "", StatusPending, "")
	for index, task := range request.Plan.Tasks {
		owner, _ := engine.registry.Owner(task.Type)
		summary.Tasks[index] = TaskExecution{TaskID: task.ID, Owner: owner, Status: StatusPending}
		summary.emit(now, "task.queued", task.ID, StatusPending, "")
	}
	if request.DryRun {
		for index := range summary.Tasks {
			_ = summary.Tasks[index].Transition(StatusSkipped, now())
			summary.emit(now, "task.skipped", summary.Tasks[index].TaskID, StatusSkipped, "dry_run")
		}
		summary.Status = StatusCompleted
		summary.emit(now, "assessment.completed", "", summary.Status, "dry_run")
		return summary, nil
	}
	if ctx.Err() != nil {
		cancelRemaining(&summary, now)
		return summary, nil
	}
	executionContext, cancel := context.WithTimeout(ctx, request.Plan.Scope.Limits.MaxDuration)
	defer cancel()
	byID := map[string]int{}
	for index, task := range request.Plan.Tasks {
		byID[task.ID] = index
	}
	completed := 0
	for completed < len(request.Plan.Tasks) {
		if executionContext.Err() != nil {
			cancelRemaining(&summary, now)
			return summary, nil
		}
		current := now().UTC()
		if !request.Plan.Scope.ExpiresAt.After(current) {
			skipRemaining(&summary, now, "authorization_expired")
			summary.Status = StatusPartial
			summary.emit(now, "assessment.completed", "", summary.Status, "authorization_expired")
			return summary, nil
		}
		if err := engine.deps.Authorize(executionContext, request.Plan.Scope); err != nil {
			skipRemaining(&summary, now, "authorization_expired")
			summary.Status = StatusPartial
			summary.emit(now, "assessment.completed", "", summary.Status, "authorization_expired")
			return summary, nil
		}
		for index, task := range request.Plan.Tasks {
			if summary.Tasks[index].Status != StatusPending || !hasNonCompletedDependency(task, summary, byID) {
				continue
			}
			if err := summary.Tasks[index].Transition(StatusBlocked, now()); err != nil {
				return ExecutionSummary{}, err
			}
			summary.Tasks[index].Reason = "dependency_failed"
			summary.emit(now, "task.blocked", task.ID, StatusBlocked, "dependency_failed")
			completed++
		}
		ready := readyTaskIndexes(request.Plan.Tasks, summary, byID)
		if len(ready) == 0 {
			break
		}
		index := ready[0]
		task := request.Plan.Tasks[index]
		execution := &summary.Tasks[index]
		ownerControlsRequests := engine.registry.OwnsRequestControls(task.Type)
		var err error
		if !ownerControlsRequests {
			err = engine.deps.RunContext.Budget.Consume(pentest.BudgetUse{Requests: 1})
			if err != nil {
				completed++
				engine.finishTask(&summary, index, err, now)
				continue
			}
		}
		if err := execution.Transition(StatusRunning, now()); err != nil {
			return ExecutionSummary{}, err
		}
		summary.emit(now, "task.started", task.ID, StatusRunning, "")
		var release func()
		if !ownerControlsRequests {
			release, err = engine.deps.RunContext.Concurrency.Acquire(executionContext)
			if err == nil {
				err = engine.deps.RunContext.Rate.Wait(executionContext)
			}
		}
		if err == nil {
			if authorizeErr := engine.deps.Authorize(executionContext, request.Plan.Scope); authorizeErr != nil {
				err = errAuthorizationExpired
			}
		}
		if err == nil {
			taskContext, cancelTask := context.WithTimeout(executionContext, taskTimeout(request))
			var result assessment.AdapterResult
			result, err = engine.registry.Dispatch(taskContext, assessment.TaskContext{AssessmentID: request.Plan.AssessmentID, Scope: request.Plan.Scope, Task: task, RunContext: engine.deps.RunContext, Now: now})
			cancelTask()
			execution.Result = result
		}
		if release != nil {
			release()
		}
		completed++
		engine.finishTask(&summary, index, err, now)
	}
	summary.Status = overallStatus(summary.Tasks)
	summary.emit(now, "assessment.completed", "", summary.Status, "")
	return summary, nil
}

func (engine Engine) validate(request ExecutionRequest) error {
	if engine.registry == nil || engine.deps.Now == nil || engine.deps.Authorize == nil || engine.deps.RunContext.Budget == nil || engine.deps.RunContext.Concurrency == nil || engine.deps.RunContext.Rate == nil || strings.TrimSpace(request.ProjectID) == "" || request.ProjectID != request.Plan.Scope.ProjectID || request.Plan.AssessmentID == "" || !request.Plan.Scope.Authorized || !validProfile(request.Plan.Scope.Profile) || request.Plan.Scope.ExpiresAt.IsZero() || !request.Plan.Scope.ExpiresAt.After(engine.deps.Now()) || request.MaxTasks < 0 || (request.MaxTasks > 0 && request.MaxTasks < len(request.Plan.Tasks)) || request.TaskTimeout < 0 || (request.TaskTimeout > 0 && request.TaskTimeout > request.Plan.Scope.Limits.MaxDuration) {
		return errors.New("invalid assessment execution request")
	}
	if err := assessment.ValidateTasks(request.Plan.Tasks); err != nil {
		return err
	}
	if err := validateDependencyGraph(request.Plan.Tasks); err != nil {
		return err
	}
	if hasSecretLikeContext(request.Plan.Scope.Target) {
		return errors.New("assessment task context contains secret-like target material")
	}
	for _, task := range request.Plan.Tasks {
		if task.AssessmentID != request.Plan.AssessmentID || task.ProjectID != request.Plan.Scope.ProjectID || task.Target != request.Plan.Scope.Target || hasSecretLikeContext(task.Target) {
			return errors.New("assessment task does not match execution scope")
		}
		if _, exists := engine.registry.Owner(task.Type); !exists {
			return errors.New("assessment task adapter is missing")
		}
	}
	return nil
}

func taskTimeout(request ExecutionRequest) time.Duration {
	if request.TaskTimeout > 0 {
		return request.TaskTimeout
	}
	return request.Plan.Scope.Limits.MaxDuration
}

func validProfile(profile assessment.Profile) bool {
	return profile == assessment.ProfileSafe || profile == assessment.ProfileStandard || profile == assessment.ProfileDeep
}

func (engine Engine) finishTask(summary *ExecutionSummary, index int, err error, now func() time.Time) {
	execution := &summary.Tasks[index]
	if err == nil {
		_ = execution.Transition(StatusCompleted, now())
		summary.emit(now, "task.completed", execution.TaskID, StatusCompleted, "")
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		_ = execution.Transition(StatusCancelled, now())
		execution.Reason = "cancelled"
		summary.emit(now, "task.cancelled", execution.TaskID, StatusCancelled, execution.Reason)
		return
	}
	if errors.Is(err, errAuthorizationExpired) {
		_ = execution.Transition(StatusCancelled, now())
		execution.Reason = "authorization_expired"
		summary.emit(now, "task.authorization_expired", execution.TaskID, StatusCancelled, execution.Reason)
		return
	}
	if strings.Contains(err.Error(), "budget exhausted") {
		_ = execution.Transition(StatusBlocked, now())
		execution.Reason = "budget_exhausted"
		summary.emit(now, "task.budget_exhausted", execution.TaskID, StatusBlocked, execution.Reason)
		return
	}
	_ = execution.Transition(StatusFailed, now())
	execution.Reason = "adapter_failed"
	summary.emit(now, "task.failed", execution.TaskID, StatusFailed, execution.Reason)
}

func (summary *ExecutionSummary) emit(now func() time.Time, eventType, taskID string, status Status, reason string) {
	summary.Events = append(summary.Events, ExecutionEvent{Type: eventType, ProjectID: summary.ProjectID, AssessmentID: summary.AssessmentID, TaskID: taskID, Status: status, Reason: reason, CreatedAt: now().UTC()})
}

func validateDependencyGraph(tasks []assessment.Task) error {
	byID := map[string]assessment.Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return errors.New("cyclic assessment task dependency")
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dependency := range byID[id].Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[id], visited[id] = false, true
		return nil
	}
	for _, task := range tasks {
		if err := visit(task.ID); err != nil {
			return err
		}
	}
	return nil
}

func readyTaskIndexes(tasks []assessment.Task, summary ExecutionSummary, byID map[string]int) []int {
	ready := []int{}
	for index, task := range tasks {
		if summary.Tasks[index].Status != StatusPending || !dependenciesCompleted(task, summary, byID) {
			continue
		}
		ready = append(ready, index)
	}
	sort.Slice(ready, func(i, j int) bool {
		left, right := tasks[ready[i]], tasks[ready[j]]
		if left.Priority != right.Priority {
			return left.Priority > right.Priority
		}
		return left.ID < right.ID
	})
	return ready
}

func dependenciesCompleted(task assessment.Task, summary ExecutionSummary, byID map[string]int) bool {
	for _, dependency := range task.Dependencies {
		if summary.Tasks[byID[dependency]].Status != StatusCompleted {
			return false
		}
	}
	return true
}

func hasNonCompletedDependency(task assessment.Task, summary ExecutionSummary, byID map[string]int) bool {
	for _, dependency := range task.Dependencies {
		status := summary.Tasks[byID[dependency]].Status
		if status == StatusFailed || status == StatusBlocked || status == StatusCancelled || status == StatusSkipped {
			return true
		}
	}
	return false
}

func cancelRemaining(summary *ExecutionSummary, now func() time.Time) {
	for index := range summary.Tasks {
		if summary.Tasks[index].Status == StatusPending {
			_ = summary.Tasks[index].Transition(StatusCancelled, now())
			summary.Tasks[index].Reason = "cancelled"
			summary.emit(now, "task.cancelled", summary.Tasks[index].TaskID, StatusCancelled, "cancelled")
		}
	}
	summary.Status = StatusCancelled
	summary.emit(now, "assessment.cancelled", "", StatusCancelled, "cancelled")
}

func skipRemaining(summary *ExecutionSummary, now func() time.Time, reason string) {
	for index := range summary.Tasks {
		if summary.Tasks[index].Status == StatusPending {
			_ = summary.Tasks[index].Transition(StatusSkipped, now())
			summary.Tasks[index].Reason = reason
			summary.emit(now, "task.skipped", summary.Tasks[index].TaskID, StatusSkipped, reason)
		}
	}
}

func overallStatus(tasks []TaskExecution) Status {
	for _, task := range tasks {
		if task.Status == StatusCancelled {
			return StatusCancelled
		}
	}
	for _, task := range tasks {
		if task.Status == StatusFailed || task.Status == StatusBlocked || task.Status == StatusSkipped {
			return StatusPartial
		}
	}
	return StatusCompleted
}

func allowedTransition(current, next Status) bool {
	return map[Status]map[Status]bool{StatusPending: {StatusRunning: true, StatusSkipped: true, StatusBlocked: true, StatusCancelled: true}, StatusRunning: {StatusCompleted: true, StatusFailed: true, StatusCancelled: true}}[current][next]
}

func terminal(status Status) bool {
	return status == StatusCompleted || status == StatusFailed || status == StatusCancelled || status == StatusSkipped || status == StatusBlocked
}

func containsSecretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "token", "secret", "authorization", "cookie", "bearer", "api_key"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hasSecretLikeContext(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil {
		return true
	}
	for key, values := range parsed.Query() {
		if containsSecretLike(key) {
			return true
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}
