// R7 execution delegates every active request to the injected R3 client. It creates no HTTP client, resolver, socket, or dialer.
package fuzzing

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

var ErrInvalidExecution = errors.New("invalid fuzz execution")

type JobState string

const (
	JobPending   JobState = "pending"
	JobRunning   JobState = "running"
	JobCompleted JobState = "completed"
	JobFailed    JobState = "failed"
	JobCancelled JobState = "cancelled"
)

type ExecutionOptions struct {
	Timeout, MaxDuration time.Duration
	MaxResponseBytes     int64
	Concurrency          int
}

type FuzzResult struct {
	MutationID string              `json:"mutation_id"`
	Response   httpengine.Response `json:"-"`
}

type FuzzJob struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	State       JobState     `json:"state"`
	Progress    int          `json:"progress"`
	Estimated   int          `json:"estimated_requests"`
	StartedAt   time.Time    `json:"started_at,omitempty"`
	CompletedAt time.Time    `json:"completed_at,omitempty"`
	Errors      []string     `json:"errors,omitempty"`
	Results     []FuzzResult `json:"-"`
}

func Run(ctx context.Context, client httpengine.Client, plan FuzzPlan, options ExecutionOptions) (FuzzJob, error) {
	job := FuzzJob{ID: plan.ID, ProjectID: plan.ProjectID, State: JobPending, Estimated: len(plan.Requests)}
	if err := ctx.Err(); err != nil {
		job.State, job.CompletedAt = JobCancelled, time.Now().UTC()
		return job, err
	}
	if client == nil || strings.TrimSpace(plan.ID) == "" || strings.TrimSpace(plan.ProjectID) == "" || !validExecutionOptions(options) {
		job.State, job.CompletedAt = JobFailed, time.Now().UTC()
		return job, ErrInvalidExecution
	}
	if options.Concurrency == 0 {
		options.Concurrency = 1
	}
	runContext, cancel := context.WithTimeout(ctx, options.MaxDuration)
	defer cancel()
	job.State, job.StartedAt = JobRunning, time.Now().UTC()
	type executionResult struct {
		result FuzzResult
		err    error
	}
	workers := options.Concurrency
	if workers > len(plan.Requests) {
		workers = len(plan.Requests)
	}
	if workers == 0 {
		job.State, job.CompletedAt = JobCompleted, time.Now().UTC()
		return job, nil
	}
	tasks := make(chan PlannedRequest)
	results := make(chan executionResult, len(plan.Requests))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				select {
				case <-runContext.Done():
					return
				case planned, open := <-tasks:
					if !open {
						return
					}
					response, err := client.Do(runContext, httpengine.Request{ProjectID: plan.ProjectID, Method: planned.Template.Method, URL: planned.Template.URL, Headers: toHTTPHeaders(planned.Template.Headers), Body: append([]byte(nil), planned.Template.Body...), Timeout: options.Timeout, MaxResponseBytes: options.MaxResponseBytes, Source: "fuzz/" + planned.Mutation.ID})
					select {
					case results <- executionResult{result: FuzzResult{MutationID: planned.Mutation.ID, Response: response}, err: err}:
					case <-runContext.Done():
					}
				}
			}
		}()
	}
	go func() {
		defer close(tasks)
		for _, planned := range plan.Requests {
			select {
			case tasks <- planned:
			case <-runContext.Done():
				return
			}
		}
	}()
	go func() { group.Wait(); close(results) }()
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
			cancel()
			continue
		}
		if result.err == nil {
			job.Results = append(job.Results, result.result)
			job.Progress++
		}
	}
	if firstErr != nil {
		job.CompletedAt = time.Now().UTC()
		if ctx.Err() != nil || errors.Is(firstErr, context.Canceled) || errors.Is(firstErr, context.DeadlineExceeded) {
			job.State = JobCancelled
			if ctx.Err() != nil {
				return job, ctx.Err()
			}
			return job, firstErr
		}
		job.State = JobFailed
		job.Errors = append(job.Errors, "R3 request failed")
		return job, firstErr
	}
	job.State, job.CompletedAt = JobCompleted, time.Now().UTC()
	return job, nil
}

func validExecutionOptions(options ExecutionOptions) bool {
	return options.Timeout > 0 && options.Timeout <= 30*time.Second && options.MaxDuration > 0 && options.MaxDuration <= 2*time.Minute && options.MaxResponseBytes >= 0 && options.MaxResponseBytes <= 16<<20 && options.Concurrency >= 0 && options.Concurrency <= 50
}

func toHTTPHeaders(headers map[string][]string) http.Header {
	if len(headers) == 0 {
		return nil
	}
	result := make(http.Header, len(headers))
	for name, values := range headers {
		result[name] = append([]string(nil), values...)
	}
	return result
}
