// R7.5 virtual-host discovery keeps the network destination fixed and varies only a validated HTTP Host override through R3.
package contentdiscovery

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type R75VHostPlan struct {
	ProjectID         string
	BaseURL           string
	HostSuffix        string
	Hosts             []string
	BaselineHost      string
	EstimatedRequests int
	Limits            R75Limits
}

// LoadR75VHostWordlist reads local hostname labels only; it never downloads or resolves entries.
func LoadR75VHostWordlist(filename string, limits R75WordlistLimits) ([]string, error) {
	if strings.TrimSpace(filename) == "" || limits.MaxFileBytes < 1 || limits.MaxFileBytes > 16<<20 || limits.MaxEntries < 1 || limits.MaxEntries > 2000 || limits.MaxEntryBytes < 1 || limits.MaxEntryBytes > 4096 {
		return nil, ErrInvalidR75Plan
	}
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalidR75Plan
	}
	if info.Size() > limits.MaxFileBytes {
		return nil, ErrR75WordlistLimit
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, ErrInvalidR75Plan
	}
	defer file.Close()
	reader := bufio.NewReaderSize(io.LimitReader(file, limits.MaxFileBytes+1), limits.MaxEntryBytes+2)
	seen := make(map[string]struct{})
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > limits.MaxEntryBytes+1 {
			return nil, ErrR75WordlistLimit
		}
		label := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, "\n")))
		if label != "" && r75ValidHostnameLabel(label) {
			seen[label] = struct{}{}
			if len(seen) > limits.MaxEntries {
				return nil, ErrR75WordlistLimit
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, ErrInvalidR75Plan
		}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	if len(labels) == 0 {
		return nil, ErrInvalidR75Plan
	}
	return labels, nil
}

// BuildR75VHostPlan accepts local hostname labels only; candidate names never alter the R3 destination URL.
func BuildR75VHostPlan(projectID, rawBaseURL, rawSuffix string, entries []string, limits R75Limits) (R75VHostPlan, error) {
	if strings.TrimSpace(projectID) == "" || limits.validate() != nil {
		return R75VHostPlan{}, ErrInvalidR75Plan
	}
	baseURL, err := normalizeR75BaseURL(rawBaseURL)
	if err != nil {
		return R75VHostPlan{}, ErrInvalidR75Plan
	}
	suffix, err := normalizeR75Hostname(rawSuffix)
	if err != nil {
		return R75VHostPlan{}, ErrInvalidR75Plan
	}
	hosts := normalizeR75VHostEntries(entries, suffix, limits.MaxEntryBytes)
	if len(hosts) == 0 || len(hosts) > limits.MaxEntries {
		return R75VHostPlan{}, ErrR75PlanLimit
	}
	estimatedRequests := len(hosts) + 1
	if estimatedRequests > limits.MaxRequests {
		return R75VHostPlan{}, ErrR75PlanLimit
	}
	return R75VHostPlan{ProjectID: projectID, BaseURL: baseURL, HostSuffix: suffix, Hosts: hosts, BaselineHost: "wraith-r75-baseline." + suffix, EstimatedRequests: estimatedRequests, Limits: limits}, nil
}

func normalizeR75VHostEntries(entries []string, suffix string, maxBytes int) []string {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		label := strings.ToLower(strings.TrimSpace(entry))
		if len(label) == 0 || len(label) > maxBytes || strings.Contains(label, ".") || !r75ValidHostnameLabel(label) {
			continue
		}
		seen[label+"."+suffix] = struct{}{}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func normalizeR75Hostname(raw string) (string, error) {
	hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if hostname == "" || len(hostname) > 253 {
		return "", ErrInvalidR75Plan
	}
	for _, label := range strings.Split(hostname, ".") {
		if !r75ValidHostnameLabel(label) {
			return "", ErrInvalidR75Plan
		}
	}
	return hostname, nil
}

func r75ValidHostnameLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

// RunR75VHosts executes the baseline and candidates through R3 at the fixed project-local base URL.
func RunR75VHosts(parent context.Context, client httpengine.Client, plan R75VHostPlan, options R75ExecutionOptions) (R75Run, error) {
	if client == nil || plan.Limits.validate() != nil || strings.TrimSpace(plan.ProjectID) == "" || len(plan.Hosts) == 0 || !strings.HasPrefix(plan.BaselineHost, "wraith-r75-baseline.") || plan.EstimatedRequests != len(plan.Hosts)+1 {
		return R75Run{}, ErrInvalidR75Execution
	}
	if err := prepareR75Options(&options, plan.Limits); err != nil {
		return R75Run{}, err
	}
	ctx, cancel := context.WithTimeout(parent, options.MaxDuration)
	defer cancel()
	baselineResponse, err := client.Do(ctx, r75VHostRequest(plan, plan.BaselineHost, options, "content-discovery.r75.vhost-baseline"))
	if err != nil {
		return R75Run{}, err
	}
	if baselineResponse.Truncated {
		return R75Run{}, httpengine.ErrResponseTooLarge
	}
	baseline := FingerprintR75(baselineResponse)
	run := R75Run{Baseline: baseline, RequestsPlanned: plan.EstimatedRequests, RequestsSent: 1}
	jobs := make(chan string)
	results := make(chan R75Result, len(plan.Hosts))
	workers := options.Concurrency
	if workers > len(plan.Hosts) {
		workers = len(plan.Hosts)
	}
	var sent sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for host := range jobs {
				response, requestErr := client.Do(ctx, r75VHostRequest(plan, host, options, "content-discovery.r75.vhost-candidate"))
				sent.Lock()
				run.RequestsSent++
				sent.Unlock()
				if requestErr != nil || response.Truncated || !r75Meaningful(response, baseline) {
					continue
				}
				fingerprint := FingerprintR75(response)
				results <- R75Result{URL: r75VHostURL(plan.BaseURL, host), Path: "/", StatusCode: response.StatusCode, ContentType: response.ContentType, ContentClass: fingerprint.ContentClass, ContentLength: fingerprint.ContentLength, Fingerprint: fingerprint.BodyHash, Similarity: SimilarityR75(baseline, fingerprint), RedirectCount: len(response.Redirects), DurationMS: response.Duration.Milliseconds()}
			}
		}()
	}
	for _, host := range plan.Hosts {
		select {
		case jobs <- host:
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

func prepareR75Options(options *R75ExecutionOptions, limits R75Limits) error {
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if options.MaxDuration <= 0 {
		options.MaxDuration = time.Duration(limits.MaxDurationSecs) * time.Second
	}
	if options.Concurrency <= 0 {
		options.Concurrency = limits.MaxConcurrency
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = limits.MaxResponseBytes
	}
	if options.Timeout > 30*time.Second || options.MaxDuration > time.Duration(limits.MaxDurationSecs)*time.Second || options.Concurrency > limits.MaxConcurrency || options.MaxResponseBytes > limits.MaxResponseBytes || options.MaxRedirects < 0 || options.MaxRedirects > 5 || options.MaxRecursionDepth < 0 || options.MaxRecursionDepth > 2 {
		return ErrInvalidR75Execution
	}
	return nil
}

func r75VHostRequest(plan R75VHostPlan, host string, options R75ExecutionOptions, source string) httpengine.Request {
	redirects := options.MaxRedirects
	return httpengine.Request{ProjectID: plan.ProjectID, Method: http.MethodGet, URL: plan.BaseURL, HostOverride: host, Headers: http.Header{"User-Agent": []string{"Wraith/r7.5-content-discovery"}}, Timeout: options.Timeout, MaxResponseBytes: options.MaxResponseBytes, MaxRedirects: &redirects, Source: source, RedirectValidator: r75RedirectValidator(plan.BaseURL)}
}

func r75VHostURL(baseURL, host string) string {
	base, _ := url.Parse(baseURL)
	if port := base.Port(); port != "" {
		base.Host = net.JoinHostPort(host, port)
	} else {
		base.Host = host
	}
	base.Path = "/"
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}
