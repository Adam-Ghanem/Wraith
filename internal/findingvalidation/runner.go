package findingvalidation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

var (
	ErrInvalidRun         = errors.New("invalid finding validation run")
	ErrPolicyDenied       = errors.New("finding validation denied by policy recheck")
	ErrServiceInstability = errors.New("finding validation stopped for service instability")
)

// PolicyRechecker is the explicit R1 re-evaluation seam called before every
// R3 dispatch. It does not resolve, dial, or otherwise create egress.
type PolicyRechecker interface {
	Recheck(context.Context, string, evidence.Endpoint) error
}

// R8Submitter persists/evaluates redacted R8-owned validation observations.
type R8Submitter interface {
	Submit(context.Context, ValidationCandidate, ValidationResult, evidence.Endpoint, httpengine.Response) ([]string, error)
}

// R9Submitter accepts only a validated candidate for R9-owned correlation.
type R9Submitter interface {
	Submit(context.Context, FindingCandidate) (string, error)
}

type RunDependencies struct {
	Client      httpengine.Client
	Budget      *pentest.BudgetManager
	Rate        *pentest.GlobalRateLimiter
	Concurrency *pentest.ConcurrencyController
	Policy      PolicyRechecker
	R8          R8Submitter
	R9          R9Submitter
}

type RunOptions struct {
	Authorized       bool
	Execute          bool
	MaxDuration      time.Duration
	MaxResponseBytes int64
}

type RunResult struct {
	Candidate     ValidationCandidate
	Result        ValidationResult
	Finding       *FindingCandidate
	CorrelationID string
	RequestsSent  int
	Metrics       Metrics
}

// Metrics is a bounded per-candidate summary for a later R10.5 lifecycle
// adapter. It performs no persistence, scheduling, or reporting itself.
type Metrics struct {
	SignalsReceived, ValidationsStarted, ValidationsCompleted int
	Validated, Rejected, Inconclusive                         int
	RequestsUsed, FindingCandidates, CorrelatedFindings       int
}

func Run(parent context.Context, candidate ValidationCandidate, plan injection.Plan, template requestmutation.RequestTemplate, parameter evidence.Parameter, dependencies RunDependencies, options RunOptions) (RunResult, error) {
	if !options.Execute {
		return RunResult{Candidate: candidate}, nil
	}
	if !options.Authorized || dependencies.Client == nil || dependencies.Budget == nil || dependencies.Rate == nil || dependencies.Concurrency == nil || dependencies.Policy == nil || dependencies.R8 == nil || dependencies.R9 == nil || options.MaxDuration <= 0 || options.MaxDuration > 10*time.Minute || options.MaxResponseBytes <= 0 || options.MaxResponseBytes > 4<<20 || !validRun(candidate, plan, template, parameter) {
		return RunResult{}, ErrInvalidRun
	}
	ctx, cancel := context.WithTimeout(parent, options.MaxDuration)
	defer cancel()
	_, payload, ok := validationTest(candidate, plan)
	if !ok {
		return RunResult{}, ErrInvalidRun
	}
	pairs := pairsFor(candidate.Profile)
	result := RunResult{Candidate: candidate, Result: ValidationResult{ValidationID: candidate.ValidationID, Status: StatusRunning}, Metrics: Metrics{SignalsReceived: 1, ValidationsStarted: 1}}
	diffs := make([]ValidationDiff, 0, pairs)
	var last httpengine.Response
	for index := 0; index < pairs; index++ {
		if err := ctx.Err(); err != nil {
			result.Result = ValidationResult{ValidationID: candidate.ValidationID, Status: StatusCancelled, StopReason: "context cancelled", RequestCount: result.RequestsSent}
			recordOutcome(&result)
			return result, err
		}
		baseline, err := dispatch(ctx, candidate, template, dependencies, "findingvalidation.r11.4.baseline", options)
		if err != nil {
			result.Result = inconclusive(candidate, result.RequestsSent, err)
			recordOutcome(&result)
			return result, err
		}
		result.RequestsSent++
		variant, err := requestmutation.ComposePayload(requestmutation.PayloadInput{ProjectID: candidate.ProjectID, Authorized: true, Template: template, Target: parameter, PayloadID: payload.PayloadID, Value: payload.Value, Limits: requestmutation.DefaultLimits()})
		if err != nil {
			return result, err
		}
		response, err := dispatch(ctx, candidate, variant.Template, dependencies, "findingvalidation.r11.4.mutation", options)
		if err != nil {
			result.Result = inconclusive(candidate, result.RequestsSent, err)
			recordOutcome(&result)
			return result, err
		}
		result.RequestsSent++
		if response.StatusCode == 429 {
			result.Result = ValidationResult{ValidationID: candidate.ValidationID, Status: StatusInconclusive, StopReason: "service instability", RequestCount: result.RequestsSent}
			recordOutcome(&result)
			return result, ErrServiceInstability
		}
		last = response
		diffs = append(diffs, Compare(snapshot(baseline), snapshot(response), payload.Value))
	}
	result.Result = Assess(candidate, diffs)
	result.Result.RequestCount = result.RequestsSent
	recordOutcome(&result)
	if result.Result.Status != StatusValidated {
		return result, nil
	}
	references, err := dependencies.R8.Submit(ctx, candidate, result.Result, template.Endpoint, last)
	if err != nil {
		return result, err
	}
	finding, err := NewFindingCandidate(candidate, result.Result, references)
	if err != nil {
		return result, err
	}
	result.Finding = &finding
	result.Metrics.FindingCandidates = 1
	correlationID, err := dependencies.R9.Submit(ctx, finding)
	if err != nil {
		return result, err
	}
	result.CorrelationID = correlationID
	if correlationID != "" {
		result.Metrics.CorrelatedFindings = 1
	}
	return result, nil
}

func recordOutcome(result *RunResult) {
	if result == nil {
		return
	}
	result.Metrics.RequestsUsed = result.RequestsSent
	result.Metrics.ValidationsCompleted = 1
	switch result.Result.Status {
	case StatusValidated:
		result.Metrics.Validated = 1
	case StatusRejected:
		result.Metrics.Rejected = 1
	case StatusInconclusive, StatusCancelled:
		result.Metrics.Inconclusive = 1
	}
}

func validRun(candidate ValidationCandidate, plan injection.Plan, template requestmutation.RequestTemplate, parameter evidence.Parameter) bool {
	return candidate.ProjectID != "" && candidate.ValidationID != "" && candidate.TestID != "" && validProfile(candidate.Profile) && validClass(candidate.InjectionClass) && candidate.EndpointID == template.Endpoint.Identity && candidate.ParameterID == parameter.Identity && candidate.ProjectID == plan.ProjectID && template.Endpoint.ProjectID == candidate.ProjectID && parameter.ProjectID == candidate.ProjectID && parameter.EndpointIdentity == template.Endpoint.Identity && (strings.EqualFold(template.Endpoint.Method, "GET") || strings.EqualFold(template.Endpoint.Method, "HEAD"))
}

func validationTest(candidate ValidationCandidate, plan injection.Plan) (injection.InjectionTest, injection.InjectionPayload, bool) {
	for _, test := range plan.Tests {
		if test.TestID == candidate.TestID && test.ProjectID == candidate.ProjectID && test.InjectionClass == candidate.InjectionClass {
			payload, ok := plan.PayloadFor(test)
			return test, payload, ok
		}
	}
	return injection.InjectionTest{}, injection.InjectionPayload{}, false
}

func pairsFor(profile Profile) int {
	switch profile {
	case ProfileDeep:
		return 3
	case ProfileStandard:
		return 2
	default:
		return 1
	}
}

func dispatch(ctx context.Context, candidate ValidationCandidate, template requestmutation.RequestTemplate, dependencies RunDependencies, source string, options RunOptions) (httpengine.Response, error) {
	if err := dependencies.Policy.Recheck(ctx, candidate.ProjectID, template.Endpoint); err != nil {
		return httpengine.Response{}, ErrPolicyDenied
	}
	if err := dependencies.Budget.Consume(pentest.BudgetUse{Requests: 1}); err != nil {
		return httpengine.Response{}, err
	}
	if err := dependencies.Rate.Wait(ctx); err != nil {
		return httpengine.Response{}, err
	}
	release, err := dependencies.Concurrency.Acquire(ctx)
	if err != nil {
		return httpengine.Response{}, err
	}
	defer release()
	redirects := 0
	return dependencies.Client.Do(ctx, httpengine.Request{ProjectID: candidate.ProjectID, Method: template.Endpoint.Method, URL: template.Endpoint.URL, Headers: cloneHeaders(template.Headers), Body: append([]byte(nil), template.Body...), Timeout: options.MaxDuration, MaxResponseBytes: options.MaxResponseBytes, MaxRedirects: &redirects, Source: source})
}

func snapshot(response httpengine.Response) ResponseSnapshot {
	return ResponseSnapshot{StatusCode: response.StatusCode, ContentType: response.ContentType, Headers: response.Headers, Body: append([]byte(nil), response.Body...), DurationMS: response.Duration.Milliseconds()}
}

func cloneHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}
	clone := make(map[string][]string, len(headers))
	for name, values := range headers {
		clone[name] = append([]string(nil), values...)
	}
	return clone
}

func inconclusive(candidate ValidationCandidate, requests int, err error) ValidationResult {
	return ValidationResult{ValidationID: candidate.ValidationID, Status: StatusInconclusive, StopReason: "controlled request failed", RequestCount: requests, EvidenceQuality: "unavailable"}
}
