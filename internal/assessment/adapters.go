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
		adapter, exists := registry.adapters[task.Type]
		if !exists {
			return errors.New("missing assessment task adapter")
		}
		result, err := adapter.Execute(taskContext, TaskContext{AssessmentID: plan.AssessmentID, Scope: plan.Scope, Task: task, RunContext: shared})
		if err != nil {
			return err
		}
		if strings.TrimSpace(result.Owner) != strings.TrimSpace(adapter.Owner()) || result.TaskID != task.ID || result.SignalCount < 0 {
			return errors.New("invalid assessment adapter result")
		}
		return nil
	}})
}

func knownTaskType(value TaskType) bool {
	switch value {
	case TaskCrawl, TaskEndpoints, TaskJS, TaskBaseline, TaskDiscovery, TaskMutation, TaskFuzz, TaskInjection, TaskValidation, TaskCorrelation, TaskFinding, TaskRisk, TaskSurface, TaskReport:
		return true
	}
	return false
}
