package assessment

import (
	"context"
	"errors"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

type ExecutionDependencies struct {
	RunContext pentest.RunContext
	Now        func() time.Time
	// RunTask is the only execution seam. Callers must supply adapters that
	// reuse R1/R3/R10.5 and the owning R7/R11 lifecycle components.
	RunTask func(context.Context, Task, pentest.RunContext) error
}

type ExecutionResult struct {
	Completed, Failed, Skipped []Task
	Reasons                    map[string]string
}

func Execute(ctx context.Context, plan AssessmentPlan, dependencies ExecutionDependencies) (ExecutionResult, error) {
	if ctx == nil || dependencies.RunContext.Budget == nil || dependencies.RunContext.Concurrency == nil || dependencies.RunContext.Rate == nil || dependencies.RunTask == nil {
		return ExecutionResult{}, errors.New("missing shared assessment execution controls")
	}
	if err := ValidateTasks(plan.Tasks); err != nil {
		return ExecutionResult{}, err
	}
	now := time.Now
	if dependencies.Now != nil {
		now = dependencies.Now
	}
	result := ExecutionResult{Reasons: map[string]string{}}
	completed := map[string]bool{}
	for _, task := range plan.Tasks {
		if err := ctx.Err(); err != nil {
			result.Skipped = append(result.Skipped, task)
			result.Reasons[task.ID] = "cancelled"
			continue
		}
		if !plan.Scope.Authorized || !plan.Scope.ExpiresAt.After(now().UTC()) {
			return result, errors.New("assessment authorization scope is expired or invalid")
		}
		ready := true
		for _, dependency := range task.Dependencies {
			if !completed[dependency] {
				ready = false
				break
			}
		}
		if !ready {
			result.Skipped = append(result.Skipped, task)
			result.Reasons[task.ID] = "dependency_failed"
			continue
		}
		if err := dependencies.RunTask(ctx, task, dependencies.RunContext); err != nil {
			result.Failed = append(result.Failed, task)
			result.Reasons[task.ID] = "adapter_failed"
			continue
		}
		completed[task.ID] = true
		result.Completed = append(result.Completed, task)
	}
	return result, nil
}
