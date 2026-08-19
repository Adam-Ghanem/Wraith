package injection

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

var (
	ErrUnsafeMethod       = errors.New("injection testing permits only GET or HEAD")
	ErrServiceInstability = errors.New("injection testing stopped for service instability")
)

type RunDependencies struct {
	// Client is the existing R3 client. R11.3 never constructs a direct client.
	Client      httpengine.Client
	Budget      *pentest.BudgetManager
	Rate        *pentest.GlobalRateLimiter
	Concurrency *pentest.ConcurrencyController
	Evidence    InjectionEvidenceSink
	Validation  ValidationSubmitter
}

type InjectionEvidenceSink interface {
	UpsertEndpoint(context.Context, evidence.Endpoint) (evidence.Endpoint, error)
	AppendObservation(context.Context, evidence.Observation) error
}

// ValidationSubmitter is an R8-owned validation handoff. R11.3 submits a signal
// but cannot create a finding or assign a confirmed vulnerability state.
type ValidationSubmitter interface {
	Submit(context.Context, InjectionSignal) error
}

type RunOptions struct {
	Authorized       bool
	Execute          bool
	MaxDuration      time.Duration
	MaxResponseBytes int64
}

type RunResult struct {
	TestsExecuted   int               `json:"tests_executed"`
	RequestsSent    int               `json:"requests_sent"`
	Signals         []InjectionSignal `json:"signals"`
	FindingsCreated int               `json:"findings_created"`
}

// Run has no network effect until Execute is explicitly set. In active mode it
// sends only a baseline and one bounded payload request for each planned test.
func Run(parent context.Context, plan Plan, dependencies RunDependencies, options RunOptions) (RunResult, error) {
	if !options.Execute {
		return RunResult{}, nil
	}
	if !options.Authorized {
		return RunResult{}, ErrUnauthorized
	}
	if dependencies.Client == nil || dependencies.Budget == nil || dependencies.Rate == nil || dependencies.Concurrency == nil || options.MaxDuration <= 0 || options.MaxDuration > 10*time.Minute || options.MaxResponseBytes <= 0 || options.MaxResponseBytes > 4<<20 || plan.ProjectID == "" || plan.template.Endpoint.ProjectID != plan.ProjectID || plan.parameter.ProjectID != plan.ProjectID {
		return RunResult{}, ErrInvalidPlan
	}
	method := strings.ToUpper(strings.TrimSpace(plan.template.Endpoint.Method))
	if method != "GET" && method != "HEAD" {
		return RunResult{}, ErrUnsafeMethod
	}
	ctx, cancel := context.WithTimeout(parent, options.MaxDuration)
	defer cancel()
	run := RunResult{Signals: make([]InjectionSignal, 0, len(plan.Tests))}
	for _, test := range plan.Tests {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		if test.ProjectID != plan.ProjectID || test.EndpointID != plan.EndpointID || test.ParameterID != plan.ParameterID || test.Status != TestPlanned {
			return run, ErrInvalidPlan
		}
		payload, ok := plan.PayloadFor(test)
		if !ok {
			return run, ErrInvalidPlan
		}
		baseline, err := dispatch(ctx, dependencies, plan.template, "injection.r11.3.baseline", options)
		run.RequestsSent++
		if err != nil {
			return run, err
		}
		variant, err := requestmutation.ComposePayload(requestmutation.PayloadInput{ProjectID: plan.ProjectID, Authorized: true, Template: plan.template, Target: plan.parameter, PayloadID: payload.PayloadID, Value: payload.Value, Limits: requestmutation.DefaultLimits()})
		if err != nil {
			return run, err
		}
		response, err := dispatch(ctx, dependencies, variant.Template, "injection.r11.3.test", options)
		run.RequestsSent++
		if err != nil {
			return run, err
		}
		if response.StatusCode == 429 {
			return run, ErrServiceInstability
		}
		signal := Analyze(test, snapshot(baseline), snapshot(response))
		if dependencies.Evidence != nil {
			if err := persistSignal(ctx, dependencies.Evidence, plan, test, signal, response); err != nil {
				return run, err
			}
		}
		if dependencies.Validation != nil {
			if err := dependencies.Validation.Submit(ctx, signal); err != nil {
				return run, err
			}
		}
		run.Signals = append(run.Signals, signal)
		run.TestsExecuted++
	}
	return run, nil
}

func persistSignal(ctx context.Context, sink InjectionEvidenceSink, plan Plan, test InjectionTest, signal InjectionSignal, response httpengine.Response) error {
	endpoint, err := sink.UpsertEndpoint(ctx, plan.template.Endpoint)
	if err != nil {
		return err
	}
	length := response.ContentLength
	if length < 0 {
		length = int64(len(response.Body))
	}
	observation, err := evidence.NewInjectionObservation(plan.ProjectID, endpoint, plan.parameter, evidence.InjectionObservationInput{RunID: plan.RunID, TestID: test.TestID, InjectionClass: string(test.InjectionClass), SignalType: string(signal.Type), Confidence: string(signal.Confidence), Fingerprint: signal.Fingerprint, ObservedAt: time.Now().UTC(), StatusCode: response.StatusCode, ContentType: response.ContentType, ContentLength: length, DurationMS: response.Duration.Milliseconds(), RedirectCount: len(response.Redirects)})
	if err != nil {
		return err
	}
	return sink.AppendObservation(ctx, observation.Record())
}

func dispatch(ctx context.Context, dependencies RunDependencies, template requestmutation.RequestTemplate, source string, options RunOptions) (httpengine.Response, error) {
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
	return dependencies.Client.Do(ctx, httpengine.Request{ProjectID: template.Endpoint.ProjectID, Method: template.Endpoint.Method, URL: template.Endpoint.URL, Headers: cloneHeaders(template.Headers), Body: append([]byte(nil), template.Body...), Timeout: options.MaxDuration, MaxResponseBytes: options.MaxResponseBytes, MaxRedirects: &redirects, Source: source})
}

func cloneHeaders(input map[string][]string) map[string][]string {
	if input == nil {
		return nil
	}
	result := make(map[string][]string, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func snapshot(response httpengine.Response) ResponseSnapshot {
	return ResponseSnapshot{StatusCode: response.StatusCode, ContentType: response.ContentType, Headers: response.Headers, Body: append([]byte(nil), response.Body...), DurationMS: response.Duration.Milliseconds()}
}
