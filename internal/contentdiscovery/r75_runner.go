// R7.5 execution has no network implementation: it dispatches every request through R3.
package contentdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

var ErrInvalidR75Execution = errors.New("invalid R7.5 content-discovery execution")

var r75Digits = regexp.MustCompile(`[0-9]+`)
var r75Spaces = regexp.MustCompile(`\s+`)

type R75ExecutionOptions struct {
	Timeout           time.Duration
	MaxDuration       time.Duration
	Concurrency       int
	MaxResponseBytes  int64
	MaxRedirects      int
	MaxRecursionDepth int
}

type R75Fingerprint struct {
	StatusCode     int    `json:"status_code"`
	ContentClass   string `json:"content_class"`
	ContentLength  int64  `json:"content_length"`
	BodyHash       string `json:"body_hash"`
	NormalizedHash string `json:"normalized_hash"`
}

type R75Result struct {
	URL           string  `json:"url"`
	Path          string  `json:"path"`
	StatusCode    int     `json:"status_code"`
	ContentType   string  `json:"content_type,omitempty"`
	ContentClass  string  `json:"content_class"`
	ContentLength int64   `json:"content_length"`
	Fingerprint   string  `json:"fingerprint"`
	Similarity    float64 `json:"baseline_similarity"`
	RedirectCount int     `json:"redirect_count"`
	DurationMS    int64   `json:"duration_ms"`
}

type R75Run struct {
	Baseline        R75Fingerprint `json:"baseline"`
	RequestsPlanned int            `json:"requests_planned"`
	RequestsSent    int            `json:"requests_sent"`
	Results         []R75Result    `json:"results"`
}

// FingerprintR75 produces bounded body metadata only; no response body is retained.
func FingerprintR75(response httpengine.Response) R75Fingerprint {
	body := response.Body
	raw := sha256.Sum256(body)
	normalized := r75Spaces.ReplaceAllString(r75Digits.ReplaceAllString(strings.ToLower(string(body)), "#"), " ")
	normalizedHash := sha256.Sum256([]byte(strings.TrimSpace(normalized)))
	length := response.ContentLength
	if length < 0 {
		length = int64(len(body))
	}
	return R75Fingerprint{StatusCode: response.StatusCode, ContentClass: ClassifyR75(response.ContentType), ContentLength: length, BodyHash: hex.EncodeToString(raw[:]), NormalizedHash: hex.EncodeToString(normalizedHash[:])}
}

// SimilarityR75 intentionally compares only fingerprint metadata and never raw bodies.
func SimilarityR75(left, right R75Fingerprint) float64 {
	if left.StatusCode != right.StatusCode || left.ContentClass != right.ContentClass {
		return 0
	}
	if left.NormalizedHash == right.NormalizedHash {
		return 1
	}
	maximum := left.ContentLength
	if right.ContentLength > maximum {
		maximum = right.ContentLength
	}
	if maximum == 0 {
		return 1
	}
	delta := left.ContentLength - right.ContentLength
	if delta < 0 {
		delta = -delta
	}
	return 1 - float64(delta)/float64(maximum)
}

func IsSoftNotFoundR75(baseline, candidate R75Fingerprint) bool {
	return baseline.StatusCode == candidate.StatusCode && SimilarityR75(baseline, candidate) >= 0.95
}

func ClassifyR75(contentType string) string {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch {
	case strings.Contains(mediaType, "html"):
		return "html"
	case strings.Contains(mediaType, "json"):
		return "json"
	case strings.Contains(mediaType, "xml"):
		return "xml"
	case strings.Contains(mediaType, "javascript") || strings.Contains(mediaType, "ecmascript"):
		return "javascript"
	case strings.HasPrefix(mediaType, "text/"):
		return "text"
	case mediaType == "":
		return "unknown"
	default:
		return "binary"
	}
}

// RunR75 sends exactly one baseline and each candidate through the provided R3 client.
func RunR75(parent context.Context, client httpengine.Client, plan R75Plan, options R75ExecutionOptions) (R75Run, error) {
	if client == nil || plan.Limits.validate() != nil || strings.TrimSpace(plan.ProjectID) == "" || len(plan.Paths) == 0 || plan.BaselinePath != r75BaselinePath || plan.EstimatedRequests != len(plan.Paths)+1 {
		return R75Run{}, ErrInvalidR75Execution
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if options.MaxDuration <= 0 {
		options.MaxDuration = time.Duration(plan.Limits.MaxDurationSecs) * time.Second
	}
	if options.Concurrency <= 0 {
		options.Concurrency = plan.Limits.MaxConcurrency
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = plan.Limits.MaxResponseBytes
	}
	if options.Timeout > 30*time.Second || options.MaxDuration > time.Duration(plan.Limits.MaxDurationSecs)*time.Second || options.Concurrency > plan.Limits.MaxConcurrency || options.MaxResponseBytes > plan.Limits.MaxResponseBytes || options.MaxRedirects < 0 || options.MaxRedirects > 5 || options.MaxRecursionDepth < 0 || options.MaxRecursionDepth > 2 {
		return R75Run{}, ErrInvalidR75Execution
	}
	ctx, cancel := context.WithTimeout(parent, options.MaxDuration)
	defer cancel()
	baselineResponse, err := client.Do(ctx, r75Request(plan, plan.BaselinePath, options, "content-discovery.r75.baseline"))
	if err != nil {
		return R75Run{}, err
	}
	if baselineResponse.Truncated {
		return R75Run{}, httpengine.ErrResponseTooLarge
	}
	baseline := FingerprintR75(baselineResponse)
	if options.MaxRecursionDepth > 0 {
		return runR75Recursive(ctx, client, plan, options, baseline)
	}
	run := R75Run{Baseline: baseline, RequestsPlanned: plan.EstimatedRequests, RequestsSent: 1}

	jobs := make(chan string)
	results := make(chan R75Result, len(plan.Paths))
	workers := options.Concurrency
	if workers > len(plan.Paths) {
		workers = len(plan.Paths)
	}
	var sent sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for candidatePath := range jobs {
				response, requestErr := client.Do(ctx, r75Request(plan, candidatePath, options, "content-discovery.r75.candidate"))
				sent.Lock()
				run.RequestsSent++
				sent.Unlock()
				if requestErr != nil || response.Truncated || !r75Meaningful(response, baseline) {
					continue
				}
				fingerprint := FingerprintR75(response)
				results <- R75Result{URL: r75URL(plan.BaseURL, candidatePath), Path: candidatePath, StatusCode: response.StatusCode, ContentType: response.ContentType, ContentClass: fingerprint.ContentClass, ContentLength: fingerprint.ContentLength, Fingerprint: fingerprint.BodyHash, Similarity: SimilarityR75(baseline, fingerprint), RedirectCount: len(response.Redirects), DurationMS: response.Duration.Milliseconds()}
			}
		}()
	}
	for _, candidatePath := range plan.Paths {
		select {
		case jobs <- candidatePath:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			close(results)
			return R75Run{}, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	for result := range results {
		run.Results = append(run.Results, result)
	}
	sort.Slice(run.Results, func(i, j int) bool { return run.Results[i].URL < run.Results[j].URL })
	if err := ctx.Err(); err != nil {
		return run, err
	}
	return run, nil
}

type r75QueuedPath struct {
	Path  string
	Depth int
}

// runR75Recursive is serial so recursive expansion remains deterministic and below the hard request limit.
func runR75Recursive(ctx context.Context, client httpengine.Client, plan R75Plan, options R75ExecutionOptions, baseline R75Fingerprint) (R75Run, error) {
	queue := make([]r75QueuedPath, 0, plan.Limits.MaxRequests-1)
	seen := make(map[string]struct{}, plan.Limits.MaxRequests-1)
	for _, candidatePath := range plan.Paths {
		queue = append(queue, r75QueuedPath{Path: candidatePath})
		seen[candidatePath] = struct{}{}
	}
	run := R75Run{Baseline: baseline, RequestsPlanned: plan.EstimatedRequests, RequestsSent: 1}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		candidate := queue[0]
		queue = queue[1:]
		response, requestErr := client.Do(ctx, r75Request(plan, candidate.Path, options, "content-discovery.r75.candidate"))
		run.RequestsSent++
		if requestErr != nil || response.Truncated || !r75Meaningful(response, baseline) {
			continue
		}
		fingerprint := FingerprintR75(response)
		run.Results = append(run.Results, R75Result{URL: r75URL(plan.BaseURL, candidate.Path), Path: candidate.Path, StatusCode: response.StatusCode, ContentType: response.ContentType, ContentClass: fingerprint.ContentClass, ContentLength: fingerprint.ContentLength, Fingerprint: fingerprint.BodyHash, Similarity: SimilarityR75(baseline, fingerprint), RedirectCount: len(response.Redirects), DurationMS: response.Duration.Milliseconds()})
		if candidate.Depth >= options.MaxRecursionDepth || fingerprint.ContentClass != "html" {
			continue
		}
		for _, child := range r75RecursiveChildren(candidate.Path, plan.Paths) {
			if run.RequestsSent+len(queue) >= plan.Limits.MaxRequests {
				break
			}
			if _, exists := seen[child]; exists {
				continue
			}
			seen[child] = struct{}{}
			queue = append(queue, r75QueuedPath{Path: child, Depth: candidate.Depth + 1})
		}
	}
	sort.Slice(run.Results, func(i, j int) bool { return run.Results[i].URL < run.Results[j].URL })
	return run, nil
}

func r75RecursiveChildren(parent string, entries []string) []string {
	children := make([]string, 0, len(entries))
	for _, entry := range entries {
		child, err := normalizeR75Path(pathpkg.Join(parent, entry), 4096)
		if err == nil {
			children = append(children, child)
		}
	}
	sort.Strings(children)
	return children
}

func r75Meaningful(response httpengine.Response, baseline R75Fingerprint) bool {
	if !r75PersistableStatus(response.StatusCode) || response.StatusCode == http.StatusNoContent {
		return false
	}
	return !IsSoftNotFoundR75(baseline, FingerprintR75(response))
}

func r75Request(plan R75Plan, requestPath string, options R75ExecutionOptions, source string) httpengine.Request {
	redirects := options.MaxRedirects
	return httpengine.Request{ProjectID: plan.ProjectID, Method: http.MethodGet, URL: r75URL(plan.BaseURL, requestPath), Headers: http.Header{"User-Agent": []string{"Wraith/r7.5-content-discovery"}}, Timeout: options.Timeout, MaxResponseBytes: options.MaxResponseBytes, MaxRedirects: &redirects, Source: source, RedirectValidator: r75RedirectValidator(plan.BaseURL)}
}

func r75URL(baseURL, requestPath string) string {
	base, _ := url.Parse(baseURL)
	base.Path = requestPath
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}

func r75RedirectValidator(baseURL string) func(string, string) error {
	base, _ := url.Parse(baseURL)
	return func(_, nextRaw string) error {
		next, err := url.Parse(nextRaw)
		if err != nil || !strings.EqualFold(base.Scheme, next.Scheme) || !strings.EqualFold(base.Host, next.Host) {
			return ErrInvalidR75Execution
		}
		return nil
	}
}
