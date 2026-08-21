package assessmentbuiltin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

const OwnerNetworkPortDiscovery = "r15.network_port_discovery"

func npdAdapter(dependencies Dependencies) func(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return func(ctx context.Context, taskContext assessment.TaskContext) (assessment.AdapterResult, error) {
		tcp, ok := dependencies.Client.(httpengine.TCPClient)
		if !ok || tcp == nil || dependencies.Outbound == nil || dependencies.Repository == nil || !validTask(taskContext, assessment.TaskNetworkPortDiscovery) {
			return assessment.AdapterResult{}, assessment.NewAdapterUnavailableError(OwnerNetworkPortDiscovery)
		}
		profile := npd.Profile(taskContext.Task.NPDProfile)
		if profile == "" {
			profile = npd.Profile(taskContext.Scope.Profile)
		}
		ports := npd.DefaultPorts(profile)
		if strings.TrimSpace(taskContext.Task.PortSpec) != "" {
			parsed, err := npd.ParsePorts(taskContext.Task.PortSpec, npd.MaxPorts)
			if err != nil {
				return assessment.AdapterResult{}, err
			}
			ports = parsed
		}
		if len(ports) == 0 {
			return assessment.AdapterResult{}, errors.New("NPD task has no bounded TCP ports")
		}
		wrapper := &t5TCPClient{
			gateway: dependencies.Outbound,
			tcp: tcp,
			trust: taskContext.Trust,
			runContext: taskContext.RunContext,
			now: dependencies.Now,
			sequence: new(atomic.Uint64),
		}
		scanner := npd.Scanner{TCP: wrapper, Now: dependencies.Now}
		plan, err := scanner.Plan(taskContext.Scope.Target, ports)
		if err != nil {
			return assessment.AdapterResult{}, err
		}
		plan.ProjectID = taskContext.Scope.ProjectID
		plan.ScopeVersion = taskContext.Scope.ScopeVersion
		plan.Profile = profile
		plan.Timeout = boundedNPDTimeout(taskContext.Scope.Limits.MaxDuration)
		result, err := scanner.Scan(ctx, plan)
		if err != nil && ctx.Err() != nil {
			return assessment.AdapterResult{}, err
		}
		if result.ProjectID != taskContext.Scope.ProjectID || result.ScopeVersion != taskContext.Scope.ScopeVersion || strings.TrimSpace(result.Target) != strings.TrimSpace(taskContext.Scope.Target) {
			return assessment.AdapterResult{}, errors.New("NPD result does not match assessment scope")
		}
		references := make([]string, 0, len(result.Ports))
		for _, portResult := range result.Ports {
			target, parseErr := policy.ParseTarget(result.Target)
			if parseErr != nil {
				return assessment.AdapterResult{}, errors.New("NPD result target is invalid")
			}
			host := target.Host
			if target.IP.IsValid() {
				host = target.IP.String()
			}
			subject := net.JoinHostPort(host, strconv.Itoa(int(portResult.Port)))
			observation, observationErr := evidence.NewNetworkPortObservation(taskContext.Scope.ProjectID, subject, evidence.NetworkPortObservationInput{
				Port: portResult.Port, Protocol: portResult.Protocol, State: string(portResult.State), ScopeVersion: taskContext.Scope.ScopeVersion,
				TaskID: taskContext.Task.ID, Authorization: taskContext.Trust.AuthorizationID, ObservedAt: portResult.ObservedAt, DurationMS: portResult.Duration.Milliseconds(),
			})
			if observationErr != nil {
				return assessment.AdapterResult{}, observationErr
			}
			if observationErr := dependencies.Repository.AppendObservation(ctx, observation.Record()); observationErr != nil {
				return assessment.AdapterResult{}, observationErr
			}
			references = append(references, observation.ID)
		}
		return assessment.AdapterResult{Owner: OwnerNetworkPortDiscovery, TaskID: taskContext.Task.ID, EvidenceRefs: references, SignalCount: len(result.Ports)}, nil
	}
}

type t5TCPClient struct {
	gateway   *outbound.Gateway
	tcp       httpengine.TCPClient
	trust     trustcontext.Context
	runContext pentest.RunContext
	now       func() time.Time
	sequence  *atomic.Uint64
}

func (client *t5TCPClient) ProbeTCP(ctx context.Context, request httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	if client == nil || client.gateway == nil || client.tcp == nil || client.sequence == nil || client.runContext.Budget == nil || client.runContext.Concurrency == nil || client.runContext.Rate == nil {
		return httpengine.TCPResponse{}, outbound.ErrOutboundDenied
	}
	if ctx == nil {
		return httpengine.TCPResponse{}, outbound.ErrOutboundDenied
	}
	if err := client.runContext.Budget.Consume(pentest.BudgetUse{Requests: 1}); err != nil {
		return httpengine.TCPResponse{}, err
	}
	release, err := client.runContext.Concurrency.Acquire(ctx)
	if err != nil {
		return httpengine.TCPResponse{}, err
	}
	defer release()
	if err := client.runContext.Rate.Wait(ctx); err != nil {
		return httpengine.TCPResponse{}, err
	}
	current := time.Now
	if client.now != nil {
		current = client.now
	}
	target, err := policy.NormalizeTarget(request.Target)
	if err != nil || target.Port == 0 {
		return httpengine.TCPResponse{}, outbound.ErrDestinationInvalid
	}
	host := target.Host
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	operation := outbound.Operation{
		ID: "npd-t5-" + request.ProjectID + "-" + client.trust.TaskID + "-" + fmt.Sprintf("%d", client.sequence.Add(1)),
		ProjectID: request.ProjectID, CapabilityID: "assessment-network-port-discovery", TaskID: client.trust.TaskID,
		AssessmentID: client.trust.AssessmentID, CampaignID: client.trust.CampaignID, BudgetReference: client.trust.BudgetReference,
		Destination: net.JoinHostPort(host, strconv.Itoa(int(target.Port))), Trust: client.trust,
		CreatedAt: current().UTC(), ExpiresAt: client.trust.ExpiresAt.UTC(),
	}
	if _, err := client.gateway.Authorize(ctx, operation); err != nil {
		return httpengine.TCPResponse{}, err
	}
	return client.tcp.ProbeTCP(ctx, request)
}

func boundedNPDTimeout(limit time.Duration) time.Duration {
	if limit <= 0 || limit > 30*time.Second {
		return 30 * time.Second
	}
	return limit
}
