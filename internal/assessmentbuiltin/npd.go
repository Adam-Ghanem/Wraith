package assessmentbuiltin

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

const OwnerNetworkPortDiscovery = "r15.network_port_discovery"

func npdAdapter(dependencies Dependencies) func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return func(ctx context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
		tcp, ok := dependencies.Client.(httpengine.TCPClient)
		if !ok || tcp == nil || !validTask(taskContext, assessment.TaskNetworkPortDiscovery) {
			return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(OwnerNetworkPortDiscovery)
		}
		ports := npd.DefaultPorts(npd.Profile(taskContext.Scope.Profile))
		if len(ports) == 0 {
			return assessment.AdapterResult{}, errors.New("NPD profile has no bounded TCP ports")
		}
		scanner := npd.Scanner{TCP: tcp, Now: dependencies.Now}
		plan, err := scanner.Plan(taskContext.Scope.Target, ports)
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		plan.ProjectID = taskContext.Scope.ProjectID
		plan.ScopeVersion = taskContext.Scope.ScopeVersion
		plan.Timeout = boundedNPDTimeout(taskContext.Scope.Limits.MaxDuration)
		result, err := scanner.Scan(ctx, plan)
		if err != nil && ctx.Err() != nil {
			return assessment.AdapterResult{}, err
		}
		if result.ProjectID != taskContext.Scope.ProjectID || result.ScopeVersion != taskContext.Scope.ScopeVersion || strings.TrimSpace(result.Target) != strings.TrimSpace(taskContext.Scope.Target) {
			return assessment.AdapterResult{}, errors.New("NPD result does not match assessment scope")
		}
		return assessment.AdapterResult{Owner: OwnerNetworkPortDiscovery, TaskID: taskContext.Task.ID, SignalCount: len(result.Ports)}, nil
	}
}

func boundedNPDTimeout(limit time.Duration) time.Duration {
	if limit <= 0 || limit > 30*time.Second {
		return 30 * time.Second
	}
	return limit
}
