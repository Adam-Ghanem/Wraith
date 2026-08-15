package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
)

type WebConfig struct {
	Concurrency  int
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
}

func (c WebConfig) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 50 {
		return errors.New("web concurrency must be between 1 and 50")
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("web timeout must be between 1ns and 30s")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 4<<20 {
		return errors.New("web response limit must be between 1 byte and 4 MiB")
	}
	if c.MaxRedirects < 0 || c.MaxRedirects > 5 {
		return errors.New("web redirect limit must be between 0 and 5")
	}
	return nil
}

type WebResult struct {
	Subdomain     string
	Scheme        string
	StatusCode    int
	Title         string
	ServerHeader  string
	ContentLength int64
	TechGuess     string
	FinalURL      string
	Alive         bool
	Error         string
}

func ProbeURL(ctx context.Context, rawURL string, config WebConfig, client *http.Client) (WebResult, error) {
	if err := config.Validate(); err != nil {
		return WebResult{}, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return WebResult{}, errors.New("HTTP URL must use http or https and contain a hostname without userinfo")
	}
	if client == nil {
		client = http.DefaultClient
	}
	result := WebResult{Scheme: parsed.Scheme, FinalURL: rawURL}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		redirects := 0
		requestClient := &http.Client{Transport: client.Transport, Jar: client.Jar, Timeout: client.Timeout}
		requestClient.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
			redirects++
			if redirects > config.MaxRedirects {
				return fmt.Errorf("redirect limit exceeded: %d", config.MaxRedirects)
			}
			if !strings.EqualFold(next.URL.Hostname(), parsed.Hostname()) {
				return errors.New("redirect target outside authorized hostname boundary")
			}
			return nil
		}
		req, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
		if requestErr != nil {
			cancel()
			return result, requestErr
		}
		req.Header.Set("User-Agent", "Wraith/Phase2-authorized-recon")
		response, requestErr := requestClient.Do(req)
		if requestErr != nil {
			cancel()
			lastErr = requestErr
			if attempt == 0 && isTimeoutError(requestErr) {
				continue
			}
			return result, requestErr
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, config.MaxBodyBytes+1))
		response.Body.Close()
		cancel()
		if readErr != nil {
			return result, readErr
		}
		if int64(len(body)) > config.MaxBodyBytes {
			return result, errors.New("HTTP response exceeded body-size limit")
		}
		result.StatusCode = response.StatusCode
		result.Alive = response.StatusCode > 0
		result.Title = extractTitle(body)
		result.ServerHeader = response.Header.Get("Server")
		result.ContentLength = response.ContentLength
		if result.ContentLength < 0 {
			result.ContentLength = int64(len(body))
		}
		result.TechGuess = GuessTechnology(response.Header, string(body))
		if response.Request != nil && response.Request.URL != nil {
			result.FinalURL = response.Request.URL.String()
		}
		return result, nil
	}
	return result, lastErr
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var generatorPattern = regexp.MustCompile(`(?is)<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+)["']`)

func extractTitle(body []byte) string {
	match := titlePattern.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}

func GuessTechnology(headers http.Header, body string) string {
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(poweredBy, "express") {
		return "express"
	}
	if strings.Contains(poweredBy, "php") {
		return "php"
	}
	if strings.Contains(poweredBy, "go") {
		return "go"
	}
	if match := generatorPattern.FindStringSubmatch(body); len(match) == 2 {
		generator := strings.ToLower(strings.TrimSpace(match[1]))
		switch {
		case strings.Contains(generator, "wordpress"):
			return "wordpress"
		case strings.Contains(generator, "drupal"):
			return "drupal"
		case strings.Contains(generator, "joomla"):
			return "joomla"
		}
	}
	if strings.Contains(server, "cloudflare") || headers.Get("CF-RAY") != "" {
		return "cloudflare"
	}
	if strings.Contains(server, "nginx") {
		return "nginx"
	}
	if strings.Contains(server, "apache") {
		return "apache"
	}
	if strings.Contains(server, "caddy") {
		return "caddy"
	}
	if strings.Contains(server, "go") {
		return "go"
	}
	return "unknown"
}

func ProbeSubdomain(ctx context.Context, subdomain string, config WebConfig, client *http.Client) []WebResult {
	name, err := enum.NormalizeDomain(subdomain)
	if err != nil {
		return []WebResult{{Subdomain: subdomain, Error: err.Error()}}
	}
	results := make([]WebResult, 0, 2)
	for _, scheme := range []string{"https", "http"} {
		result, err := ProbeURL(ctx, scheme+"://"+name, config, client)
		result.Subdomain = name
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	return results
}

func ProbeSubdomains(ctx context.Context, subdomains []string, config WebConfig, client *http.Client) []WebResult {
	if err := config.Validate(); err != nil {
		return []WebResult{{Error: err.Error()}}
	}
	names := enum.DeduplicateSubdomains(subdomains)
	results := make([][]WebResult, len(names))
	jobs := make(chan int)
	workers := config.Concurrency
	if workers > len(names) {
		workers = len(names)
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = ProbeSubdomain(ctx, names[index], config, client)
			}
		}()
	}
	for index := range names {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return flattenResults(results)
		}
	}
	close(jobs)
	wg.Wait()
	return flattenResults(results)
}

func flattenResults(grouped [][]WebResult) []WebResult {
	results := make([]WebResult, 0)
	for _, group := range grouped {
		results = append(results, group...)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Subdomain == results[j].Subdomain {
			return results[i].Scheme < results[j].Scheme
		}
		return results[i].Subdomain < results[j].Subdomain
	})
	return results
}
