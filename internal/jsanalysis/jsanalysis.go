package jsanalysis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
)

type FindingType string

const (
	FindingTypeEndpoint FindingType = "endpoint"
	FindingTypeSecret   FindingType = "secret"
)

type Finding struct {
	Subdomain   string      `json:"subdomain"`
	SourceFile  string      `json:"source_file"`
	FindingType FindingType `json:"finding_type"`
	Value       string      `json:"value"`
	Confidence  string      `json:"confidence"`
}

type Config struct {
	Concurrency      int
	PerHostPerSecond int
	Timeout          time.Duration
	MaxFileBytes     int64
	MaxFindings      int
}

func (c Config) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 50 {
		return errors.New("JS concurrency must be between 1 and 50")
	}
	if c.PerHostPerSecond < 1 || c.PerHostPerSecond > 20 {
		return errors.New("JS per-host rate must be between 1 and 20 per second")
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("JS timeout must be between 1ns and 30s")
	}
	if c.MaxFileBytes < 1 || c.MaxFileBytes > 5<<20 {
		return errors.New("JS file limit must be between 1 byte and 5 MiB")
	}
	if c.MaxFindings < 1 || c.MaxFindings > 50 {
		return errors.New("JS finding limit must be between 1 and 50")
	}
	return nil
}

type AnalysisResult struct {
	Subdomain   string    `json:"subdomain"`
	ScriptFiles []string  `json:"script_files"`
	Findings    []Finding `json:"findings"`
}

var scriptTagPattern = regexp.MustCompile(`(?is)<script\b[^>]*>`)
var scriptSourcePattern = regexp.MustCompile(`(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
var endpointPattern = regexp.MustCompile(`(?i)/api(?:/v[0-9]+)?/[A-Za-z0-9_./?=&{}:%-]+|/v[0-9]+/[A-Za-z0-9_./?=&{}:%-]+`)
var awsKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
var apiKeyPattern = regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']`)
var jwtPattern = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)

func ExtractScriptURLs(baseURL string, body []byte) ([]string, error) {
	base, err := parseAuthorizedURL(baseURL)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	urls := make([]string, 0)
	for _, tag := range scriptTagPattern.FindAll(body, -1) {
		match := scriptSourcePattern.FindSubmatch(tag)
		if len(match) == 0 {
			continue
		}
		rawSource := firstSubmatch(match[1:])
		if rawSource == "" {
			continue
		}
		reference, err := url.Parse(strings.TrimSpace(rawSource))
		if err != nil || reference.IsAbs() && (reference.Scheme != "http" && reference.Scheme != "https") {
			continue
		}
		resolved := base.ResolveReference(reference)
		if resolved.Scheme != "http" && resolved.Scheme != "https" || !strings.EqualFold(resolved.Hostname(), base.Hostname()) || resolved.User != nil {
			continue
		}
		resolved.Fragment = ""
		value := resolved.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		urls = append(urls, value)
	}
	sort.Strings(urls)
	return urls, nil
}

func firstSubmatch(values [][]byte) string {
	for _, value := range values {
		if len(value) != 0 {
			return string(value)
		}
	}
	return ""
}

func ExtractFindings(sourceFile string, body []byte) []Finding {
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})
	add := func(kind FindingType, value, confidence string) {
		key := string(kind) + "\x00" + value
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		if kind == FindingTypeSecret {
			// Secret values are pattern evidence only. Never log, validate, use, or persist the full match.
			value = RedactSecret(value)
		}
		findings = append(findings, Finding{SourceFile: sourceFile, FindingType: kind, Value: value, Confidence: confidence})
	}
	text := string(body)
	for _, value := range endpointPattern.FindAllString(text, -1) {
		value = strings.TrimRight(value, "'\"`),.; ")
		if strings.HasPrefix(value, "/api/") || strings.HasPrefix(value, "/api/v") || strings.HasPrefix(value, "/v") {
			add(FindingTypeEndpoint, value, "observed")
		}
	}
	for _, value := range awsKeyPattern.FindAllString(text, -1) {
		add(FindingTypeSecret, value, "potential")
	}
	for _, match := range apiKeyPattern.FindAllStringSubmatch(text, -1) {
		if len(match) == 2 {
			add(FindingTypeSecret, match[1], "potential")
		}
	}
	for _, value := range jwtPattern.FindAllString(text, -1) {
		add(FindingTypeSecret, value, "potential")
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].FindingType == findings[j].FindingType {
			return findings[i].Value < findings[j].Value
		}
		return findings[i].FindingType < findings[j].FindingType
	})
	return findings
}

func RedactSecret(value string) string {
	if len(value) <= 8 {
		return "REDACTED"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

func AnalyzeHTML(ctx context.Context, subdomain, pageURL string, htmlBody []byte, config Config, client *http.Client) (AnalysisResult, error) {
	if err := config.Validate(); err != nil {
		return AnalysisResult{}, err
	}
	scriptURLs, err := ExtractScriptURLs(pageURL, htmlBody)
	if err != nil {
		return AnalysisResult{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	limiter, err := enum.NewRateLimiter(config.PerHostPerSecond)
	if err != nil {
		return AnalysisResult{}, err
	}
	grouped := make([][]Finding, len(scriptURLs))
	jobs := make(chan int)
	workers := config.Concurrency
	if workers > len(scriptURLs) {
		workers = len(scriptURLs)
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				if err := limiter.Wait(ctx); err != nil {
					continue
				}
				body, fetchErr := fetchJS(ctx, scriptURLs[index], config, client)
				if fetchErr != nil {
					continue
				}
				grouped[index] = ExtractFindings(scriptURLs[index], body)
			}
		}()
	}
	for index := range scriptURLs {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return AnalysisResult{}, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})
	for _, group := range grouped {
		for _, finding := range group {
			key := string(finding.FindingType) + "\x00" + finding.Value
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			finding.Subdomain = subdomain
			findings = append(findings, finding)
			if len(findings) >= config.MaxFindings {
				break
			}
		}
		if len(findings) >= config.MaxFindings {
			break
		}
	}
	return AnalysisResult{Subdomain: subdomain, ScriptFiles: scriptURLs, Findings: findings}, nil
}

func fetchJS(ctx context.Context, rawURL string, config Config, client *http.Client) ([]byte, error) {
	parsed, err := parseAuthorizedURL(rawURL)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		requestClient := &http.Client{Transport: client.Transport, Jar: client.Jar, Timeout: client.Timeout}
		redirects := 0
		requestClient.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
			redirects++
			if redirects > 5 || !strings.EqualFold(next.URL.Hostname(), parsed.Hostname()) {
				return errors.New("JS redirect outside bounded same-host policy")
			}
			return nil
		}
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
		if requestErr != nil {
			cancel()
			return nil, requestErr
		}
		request.Header.Set("User-Agent", "Wraith/Phase3-authorized-js")
		response, requestErr := requestClient.Do(request)
		if requestErr != nil {
			cancel()
			lastErr = requestErr
			if attempt == 0 && isTimeout(requestErr) {
				continue
			}
			return nil, requestErr
		}
		if response.ContentLength > config.MaxFileBytes {
			response.Body.Close()
			cancel()
			return nil, errors.New("JS file exceeds size limit")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, config.MaxFileBytes+1))
		response.Body.Close()
		cancel()
		if readErr != nil {
			return nil, readErr
		}
		if int64(len(body)) > config.MaxFileBytes {
			return nil, errors.New("JS file exceeds size limit")
		}
		return body, nil
	}
	return nil, lastErr
}

func parseAuthorizedURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("URL must use http or https and contain a hostname without userinfo")
	}
	return parsed, nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkErr interface{ Timeout() bool }
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func AnalyzePage(ctx context.Context, subdomain, pageURL string, config Config, client *http.Client) (AnalysisResult, error) {
	if err := config.Validate(); err != nil {
		return AnalysisResult{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	body, err := fetchJS(ctx, pageURL, config, client)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("fetch HTML page: %w", err)
	}
	return AnalyzeHTML(ctx, subdomain, pageURL, body, config, client)
}
