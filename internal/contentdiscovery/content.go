package contentdiscovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type Config struct {
	Concurrency      int
	PerHostPerSecond int
	Timeout          time.Duration
	MaxBodyBytes     int64
	MaxRedirects     int
	Wordlist         []string
}

func (c Config) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 50 {
		return errors.New("content concurrency must be between 1 and 50")
	}
	if c.PerHostPerSecond < 1 || c.PerHostPerSecond > 20 {
		return errors.New("content per-host rate must be between 1 and 20 per second")
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("content timeout must be between 1ns and 30s")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 4<<20 {
		return errors.New("content response limit must be between 1 byte and 4 MiB")
	}
	if c.MaxRedirects < 0 || c.MaxRedirects > 5 {
		return errors.New("content redirect limit must be between 0 and 5")
	}
	return nil
}

type Response struct {
	StatusCode int
	Body       []byte
}

func (r Response) ResponseLength() int64 { return int64(len(r.Body)) }

type Baseline struct {
	StatusCode     int
	ResponseLength int64
	BodyHash       string
}

type Finding struct {
	Subdomain      string
	Path           string
	StatusCode     int
	ResponseLength int64
	DiscoveredAt   string
}

func HashBody(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func IsMeaningfulFinding(response Response, baseline Baseline) bool {
	switch response.StatusCode {
	case http.StatusOK, http.StatusMovedPermanently, http.StatusFound, http.StatusForbidden:
	default:
		return false
	}
	if response.StatusCode != baseline.StatusCode {
		return true
	}
	if response.ResponseLength() != baseline.ResponseLength {
		return true
	}
	return HashBody(response.Body) != baseline.BodyHash
}

func NormalizePath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("path must not be empty")
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "//") {
		return "", errors.New("path must be a relative path")
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return "", errors.New("path must not escape the host root")
		}
	}
	cleaned := pathpkg.Clean(value)
	if cleaned == "." || !strings.HasPrefix(cleaned, "/") {
		return "", errors.New("path must be rooted at /")
	}
	return cleaned, nil
}

// Discover compares bounded same-host paths through the shared R3 transport.
// projectID is mandatory to keep every outbound request inside the R1 boundary.
func Discover(ctx context.Context, baseURL string, config Config, projectID string, client httpengine.Client) ([]Finding, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(config.Wordlist) == 0 || len(config.Wordlist) > 200 {
		return nil, errors.New("content wordlist must contain between 1 and 200 paths")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("content base URL must use http or https and contain a hostname without userinfo")
	}
	if strings.TrimSpace(projectID) == "" || client == nil {
		return nil, errors.New("project-scoped HTTP transport is required")
	}
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	base := parsed.String()
	limiter, err := enum.NewRateLimiter(config.PerHostPerSecond)
	if err != nil {
		return nil, err
	}
	randomSuffix := make([]byte, 8)
	if _, err := rand.Read(randomSuffix); err != nil {
		return nil, fmt.Errorf("generate baseline path: %w", err)
	}
	baselinePath := "/.wraith-baseline-" + hex.EncodeToString(randomSuffix)
	if err := limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("content baseline rate limit: %w", err)
	}
	baselineResponse, err := fetch(ctx, base, baselinePath, config, projectID, client)
	if err != nil {
		return nil, fmt.Errorf("content baseline request: %w", err)
	}
	baseline := Baseline{StatusCode: baselineResponse.StatusCode, ResponseLength: baselineResponse.ResponseLength(), BodyHash: HashBody(baselineResponse.Body)}
	paths := make([]string, 0, len(config.Wordlist))
	seen := make(map[string]struct{}, len(config.Wordlist))
	for _, rawPath := range config.Wordlist {
		path, normalizeErr := NormalizePath(rawPath)
		if normalizeErr != nil {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, errors.New("content wordlist contains no valid paths")
	}
	results := make([]Finding, len(paths))
	valid := make([]bool, len(paths))
	jobs := make(chan int)
	workers := config.Concurrency
	if workers > len(paths) {
		workers = len(paths)
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
				response, requestErr := fetch(ctx, base, paths[index], config, projectID, client)
				if requestErr != nil || !IsMeaningfulFinding(response, baseline) {
					continue
				}
				results[index] = Finding{Path: paths[index], StatusCode: response.StatusCode, ResponseLength: response.ResponseLength(), DiscoveredAt: time.Now().UTC().Format(time.RFC3339)}
				valid[index] = true
			}
		}()
	}
	for index := range paths {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	findings := make([]Finding, 0)
	for index, finding := range results {
		if valid[index] {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

func fetch(ctx context.Context, baseURL, requestPath string, config Config, projectID string, client httpengine.Client) (Response, error) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return Response{}, err
	}
	path, err := NormalizePath(requestPath)
	if err != nil {
		return Response{}, err
	}
	requestURL := *parsedBase
	requestURL.Path = path
	requestURL.RawPath = ""
	requestURL.RawQuery = ""
	requestURL.Fragment = ""
	response, err := client.Do(ctx, httpengine.Request{
		ProjectID:        projectID,
		Method:           http.MethodGet,
		URL:              requestURL.String(),
		Headers:          http.Header{"User-Agent": []string{"Wraith/Phase3-authorized-content"}},
		Timeout:          config.Timeout,
		MaxResponseBytes: config.MaxBodyBytes,
		MaxRedirects:     &config.MaxRedirects,
		Source:           "phase3/content-discovery",
		RedirectValidator: func(_, nextURL string) error {
			next, parseErr := url.Parse(nextURL)
			if parseErr != nil || !strings.EqualFold(next.Hostname(), parsedBase.Hostname()) {
				return errors.New("redirect target outside authorized hostname boundary")
			}
			return nil
		},
	})
	if err != nil {
		return Response{}, err
	}
	if response.Truncated {
		return Response{}, errors.New("content response exceeded body-size limit")
	}
	return Response{StatusCode: response.StatusCode, Body: response.Body}, nil
}
