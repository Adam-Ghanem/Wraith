package assessment

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

// TaskContext carries references and shared controls to an owner adapter. It
// deliberately excludes credentials, cookies, authorization headers, payloads,
// and raw evidence values.
type TaskContext struct {
	AssessmentID string
	CampaignID   string
	Scope        ScopeSnapshot
	Task         Task
	Trust        trustcontext.Context
	RunContext   pentest.RunContext
	Now          func() time.Time
}

type AdapterResult struct {
	Owner, TaskID string
	EvidenceRefs  []string
	SignalCount   int
}

type AdapterErrorCode string

const AdapterUnavailable AdapterErrorCode = "ADAPTER_UNAVAILABLE"

// AdapterError identifies a fail-closed owner state without exposing target,
// credential, request, or evidence data to callers.
type AdapterError struct {
	Code  AdapterErrorCode
	Owner string
}

func (err *AdapterError) Error() string {
	if err == nil || strings.TrimSpace(err.Owner) == "" {
		return string(AdapterUnavailable)
	}
	return string(err.Code) + ": " + strings.TrimSpace(err.Owner)
}

func NewAdapterUnavailableError(owner string) error {
	return &AdapterError{Code: AdapterUnavailable, Owner: owner}
}

// TaskAdapter is an owner-specific bridge to an existing R4–R11 component.
// Implementations performing requests must use the injected R1/R3/R10.5
// controls; the registry itself owns no transport behavior.
type TaskAdapter interface {
	Owner() string
	Execute(context.Context, TaskContext) (AdapterResult, error)
}

// RequestControlOwner is implemented only by adapters that acquire the shared
// R10.5 controls around each individual request they delegate to an existing
// owner. It prevents a task-wide lease from deadlocking nested owner requests.
type RequestControlOwner interface {
	OwnsRequestControls() bool
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
	return ExecutionResult{}, trustcontext.ErrTrustContextMissing
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

// OwnsRequestControls reports whether an owner adapter safely consumes the
// supplied RunContext before every delegated request. Missing owners are false.
func (registry AdapterRegistry) OwnsRequestControls(taskType TaskType) bool {
	adapter, exists := registry.adapters[taskType]
	if !exists || adapter == nil {
		return false
	}
	owner, ok := adapter.(RequestControlOwner)
	return ok && owner.OwnsRequestControls()
}

// Dispatch invokes one owner adapter through the same identity and
// secret-minimized context validation used by Execute. It owns no transport.
func (registry AdapterRegistry) Dispatch(ctx context.Context, taskContext TaskContext) (AdapterResult, error) {
	now := time.Now
	if taskContext.Now != nil {
		now = taskContext.Now
	}
	if len(registry.adapters) == 0 || ctx == nil || taskContext.RunContext.Budget == nil || taskContext.RunContext.Concurrency == nil || taskContext.RunContext.Rate == nil || taskContext.AssessmentID == "" || taskContext.AssessmentID != taskContext.Task.AssessmentID || taskContext.Scope.ProjectID == "" || taskContext.Scope.ProjectID != taskContext.Task.ProjectID || taskContext.Scope.Target != taskContext.Task.Target || invalidTaskTarget(taskContext.Scope.Target) || !taskContext.Scope.Authorized || taskContext.Scope.ExpiresAt.IsZero() || !taskContext.Scope.ExpiresAt.After(now().UTC()) || !validLimits(taskContext.Scope.Limits) || !knownTaskType(taskContext.Task.Type) {
		return AdapterResult{}, errors.New("invalid assessment task context")
	}
	if err := trustcontext.Validate(taskContext.Trust, trustcontext.ValidationRequest{ProjectID: taskContext.Scope.ProjectID, ScopeVersion: taskContext.Scope.ScopeVersion, TaskID: taskContext.Task.ID, AssessmentID: taskContext.AssessmentID, CampaignID: taskContext.CampaignID, Now: now().UTC()}); err != nil {
		return AdapterResult{}, err
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

func invalidTaskTarget(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return true
	}
	for key := range parsed.Query() {
		if secretLikeTargetKey(key) {
			return true
		}
	}
	return false
}

func secretLikeTargetKey(value string) bool {
	return dataclassification.IsSecretName(value)
}

func invalidEvidenceRefs(references []string) bool {
	for _, reference := range references {
		value := strings.TrimSpace(reference)
		if value == "" || dataclassification.ValidateSafeReference(value) != nil {
			return true
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
