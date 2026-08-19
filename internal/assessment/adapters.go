package assessment

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

// TaskContext carries references and shared controls to an owner adapter. It
// deliberately excludes credentials, cookies, authorization headers, payloads,
// and raw evidence values.
type TaskContext struct {
	AssessmentID string
	Scope        ScopeSnapshot
	Task         Task
	RunContext   pentest.RunContext
	Now          func() time.Time
}

type AdapterResult struct {
	Owner, TaskID string
	EvidenceRefs  []string
	SignalCount   int
}

// TaskAdapter is an owner-specific bridge to an existing R4–R11 component.
// Implementations performing requests must use the injected R1/R3/R10.5
// controls; the registry itself owns no transport behavior.
type TaskAdapter interface {
	Owner() string
	Execute(context.Context, TaskContext) (AdapterResult, error)
}

type TypedAdapter struct {
	TaskType TaskType
	Adapter  TaskAdapter
}

type AdapterRegistry struct{ adapters map[TaskType]TaskAdapter }

func NewAdapterRegistry(values ...TypedAdapter) (AdapterRegistry, error) {
	registry := AdapterRegistry{adapters: map[TaskType]TaskAdapter{}}
	for _, value := range values {
		if value.Adapter == nil || !knownTaskType(value.TaskType) || strings.TrimSpace(value.Adapter.Owner()) == "" {
			return AdapterRegistry{}, errors.New("invalid task adapter")
		}
		if _, exists := registry.adapters[value.TaskType]; exists {
			return AdapterRegistry{}, errors.New("duplicate task adapter owner")
		}
		registry.adapters[value.TaskType] = value.Adapter
	}
	return registry, nil
}

func (registry AdapterRegistry) Execute(ctx context.Context, plan AssessmentPlan, runContext pentest.RunContext, now func() time.Time) (ExecutionResult, error) {
	if len(registry.adapters) == 0 {
		return ExecutionResult{}, errors.New("assessment adapter registry is empty")
	}
	return Execute(ctx, plan, ExecutionDependencies{RunContext: runContext, Now: now, RunTask: func(taskContext context.Context, task Task, shared pentest.RunContext) error {
		_, err := registry.Dispatch(taskContext, TaskContext{AssessmentID: plan.AssessmentID, Scope: plan.Scope, Task: task, RunContext: shared, Now: now})
		return err
	}})
}

// Owner returns the registered owner for a known task type. It allows an
// execution coordinator to fail an entire plan before it starts work when a
// required owner is absent.
func (registry AdapterRegistry) Owner(taskType TaskType) (string, bool) {
	adapter, exists := registry.adapters[taskType]
	if !exists || adapter == nil || strings.TrimSpace(adapter.Owner()) == "" {
		return "", false
	}
	return strings.TrimSpace(adapter.Owner()), true
}

// Dispatch invokes one owner adapter through the same identity and
// secret-minimized context validation used by Execute. It owns no transport.
func (registry AdapterRegistry) Dispatch(ctx context.Context, taskContext TaskContext) (AdapterResult, error) {
	now := time.Now
	if taskContext.Now != nil {
		now = taskContext.Now
	}
	if len(registry.adapters) == 0 || ctx == nil || taskContext.RunContext.Budget == nil || taskContext.RunContext.Concurrency == nil || taskContext.RunContext.Rate == nil || taskContext.AssessmentID == "" || taskContext.AssessmentID != taskContext.Task.AssessmentID || taskContext.Scope.ProjectID == "" || taskContext.Scope.ProjectID != taskContext.Task.ProjectID || taskContext.Scope.Target != taskContext.Task.Target || !taskContext.Scope.Authorized || taskContext.Scope.ExpiresAt.IsZero() || !taskContext.Scope.ExpiresAt.After(now().UTC()) || !knownTaskType(taskContext.Task.Type) {
		return AdapterResult{}, errors.New("invalid assessment task context")
	}
	adapter, exists := registry.adapters[taskContext.Task.Type]
	if !exists {
		return AdapterResult{}, errors.New("missing assessment task adapter")
	}
	result, err := adapter.Execute(ctx, taskContext)
	if err != nil {
		return AdapterResult{}, err
	}
	if strings.TrimSpace(result.Owner) != strings.TrimSpace(adapter.Owner()) || result.TaskID != taskContext.Task.ID || result.SignalCount < 0 || invalidEvidenceRefs(result.EvidenceRefs) {
		return AdapterResult{}, errors.New("invalid assessment adapter result")
	}
	return result, nil
}

func invalidEvidenceRefs(references []string) bool {
	for _, reference := range references {
		value := strings.TrimSpace(reference)
		if value == "" || len(value) > 512 {
			return true
		}
		lower := strings.ToLower(value)
		for _, marker := range []string{"password", "token=", "token:", "secret", "authorization", "cookie", "bearer", "api_key", "apikey"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

func knownTaskType(value TaskType) bool {
	switch value {
	case TaskCrawl, TaskEndpoints, TaskJS, TaskBaseline, TaskDiscovery, TaskMutation, TaskFuzz, TaskInjection, TaskValidation, TaskCorrelation, TaskFinding, TaskRisk, TaskSurface, TaskReport:
		return true
	}
	return false
}
