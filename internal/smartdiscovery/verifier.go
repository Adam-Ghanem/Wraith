package smartdiscovery

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

var (
	ErrInvalidVerification = errors.New("invalid smart discovery verification")
	ErrUnauthorizedVerify  = errors.New("smart discovery verification requires authorization")
)

type VerificationStatus string

const (
	VerificationNotFound     VerificationStatus = "not_found"
	VerificationFound        VerificationStatus = "found"
	VerificationRedirect     VerificationStatus = "redirect"
	VerificationForbidden    VerificationStatus = "forbidden"
	VerificationUnauthorized VerificationStatus = "unauthorized"
	VerificationRateLimited  VerificationStatus = "rate_limited"
	VerificationServerError  VerificationStatus = "server_error"
	VerificationTimeout      VerificationStatus = "timeout"
	VerificationNetworkError VerificationStatus = "network_error"
	VerificationUnknown      VerificationStatus = "unknown"
)

type VerificationDependencies struct {
	// Client is the existing R3 httpengine.Client contract. R11.2 never creates
	// or wraps a direct HTTP client.
	Client      httpengine.Client
	Budget      *pentest.BudgetManager
	Rate        *pentest.GlobalRateLimiter
	Concurrency *pentest.ConcurrencyController
	Evidence    DiscoveryEvidenceSink
}

type DiscoveryEvidenceSink interface {
	UpsertEndpoint(context.Context, evidence.Endpoint) (evidence.Endpoint, error)
	AppendObservation(context.Context, evidence.Observation) error
}

type VerificationOptions struct {
	Authorized       bool
	Verify           bool
	MaxDuration      time.Duration
	MaxResponseBytes int64
}

type VerificationResult struct {
	CandidateID string             `json:"candidate_id"`
	Status      VerificationStatus `json:"status"`
	StatusCode  int                `json:"status_code,omitempty"`
	ContentType string             `json:"content_type,omitempty"`
	Length      int64              `json:"content_length,omitempty"`
	DurationMS  int64              `json:"duration_ms,omitempty"`
}

type VerificationRun struct {
	RequestsSent int                  `json:"requests_sent"`
	Results      []VerificationResult `json:"results"`
}

// Verify only performs network work when Verify is explicitly true. Every
// request is a HEAD request dispatched through R3 and consumes the supplied
// R10.5 global request budget before transmission.
func Verify(parent context.Context, candidates []DiscoveryCandidate, dependencies VerificationDependencies, options VerificationOptions) (VerificationRun, error) {
	if !options.Verify {
		return VerificationRun{}, nil
	}
	if !options.Authorized {
		return VerificationRun{}, ErrUnauthorizedVerify
	}
	if dependencies.Client == nil || dependencies.Budget == nil || dependencies.Rate == nil || dependencies.Concurrency == nil || options.MaxDuration <= 0 || options.MaxDuration > 10*time.Minute || options.MaxResponseBytes <= 0 || options.MaxResponseBytes > 4<<20 {
		return VerificationRun{}, ErrInvalidVerification
	}
	ctx, cancel := context.WithTimeout(parent, options.MaxDuration)
	defer cancel()
	run := VerificationRun{Results: make([]VerificationResult, 0, len(candidates))}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		if strings.TrimSpace(candidate.ProjectID) == "" || candidate.Status != CandidatePlanned || !verifiable(candidate) {
			return run, ErrInvalidVerification
		}
		if err := dependencies.Budget.Consume(pentest.BudgetUse{Requests: 1}); err != nil {
			return run, err
		}
		if err := dependencies.Rate.Wait(ctx); err != nil {
			return run, err
		}
		release, err := dependencies.Concurrency.Acquire(ctx)
		if err != nil {
			return run, err
		}
		redirects := 0
		response, requestErr := dependencies.Client.Do(ctx, httpengine.Request{ProjectID: candidate.ProjectID, Method: "HEAD", URL: candidate.Value, Timeout: options.MaxDuration, MaxResponseBytes: options.MaxResponseBytes, MaxRedirects: &redirects, Source: "smart-discovery.r11.2.verify"})
		release()
		run.RequestsSent++
		result := VerificationResult{CandidateID: candidate.CandidateID}
		if requestErr != nil {
			result.Status = classifyError(requestErr, ctx)
		} else {
			result.Status = classifyResponse(response.StatusCode)
			result.StatusCode = response.StatusCode
			result.ContentType = response.ContentType
			result.Length = response.ContentLength
			result.DurationMS = response.Duration.Milliseconds()
			if dependencies.Evidence != nil {
				if err := persistVerificationEvidence(ctx, dependencies.Evidence, candidate, result, response); err != nil {
					return run, err
				}
			}
		}
		run.Results = append(run.Results, result)
	}
	sort.Slice(run.Results, func(left, right int) bool { return run.Results[left].CandidateID < run.Results[right].CandidateID })
	return run, nil
}

func persistVerificationEvidence(ctx context.Context, sink DiscoveryEvidenceSink, candidate DiscoveryCandidate, result VerificationResult, response httpengine.Response) error {
	endpoint, err := evidence.NewEndpoint(candidate.ProjectID, "HEAD", candidate.Value, time.Now().UTC())
	if err != nil {
		return err
	}
	endpoint, err = sink.UpsertEndpoint(ctx, endpoint)
	if err != nil {
		return err
	}
	length := response.ContentLength
	if length < 0 {
		length = 0
	}
	observation, err := evidence.NewDiscoveryObservation(candidate.ProjectID, endpoint, evidence.DiscoveryObservationInput{CandidateID: candidate.CandidateID, CandidateType: string(candidate.Type), VerificationStatus: string(result.Status), ObservedAt: time.Now().UTC(), StatusCode: response.StatusCode, ContentType: response.ContentType, ContentLength: length, DurationMS: response.Duration.Milliseconds(), RedirectCount: len(response.Redirects)})
	if err != nil {
		return err
	}
	return sink.AppendObservation(ctx, observation.Record())
}

func verifiable(candidate DiscoveryCandidate) bool {
	switch candidate.Type {
	case CandidateEndpoint, CandidatePath, CandidateAPIRoute, CandidateAPIVersion, CandidateStaticResource, CandidateDocumentation, CandidateBackupLikeResource, CandidateConfigurationLikeResource:
	default:
		return false
	}
	parsed, err := url.Parse(candidate.Value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil
}

func classifyResponse(status int) VerificationStatus {
	switch {
	case status == 404:
		return VerificationNotFound
	case status >= 200 && status < 300:
		return VerificationFound
	case status >= 300 && status < 400:
		return VerificationRedirect
	case status == 401:
		return VerificationUnauthorized
	case status == 403:
		return VerificationForbidden
	case status == 429:
		return VerificationRateLimited
	case status >= 500 && status < 600:
		return VerificationServerError
	default:
		return VerificationUnknown
	}
}

func classifyError(err error, ctx context.Context) VerificationStatus {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return VerificationTimeout
	}
	return VerificationNetworkError
}
