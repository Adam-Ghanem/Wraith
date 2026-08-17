package enum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	defaultCRTBaseURL = "https://crt.sh/"
	defaultVTBaseURL  = "https://www.virustotal.com/api/v3"
	defaultMaxBytes   = 2 << 20
)

type CRTSource struct {
	BaseURL  string
	Client   *http.Client
	Timeout  time.Duration
	MaxBytes int64
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func ParseCRTNames(body []byte, domain string) ([]string, error) {
	normalizedDomain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse crt.sh JSON: %w", err)
	}
	values := make([]string, 0)
	for _, entry := range entries {
		for _, rawName := range strings.Split(entry.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(rawName, "*.")))
			if name == normalizedDomain || strings.HasSuffix(name, "."+normalizedDomain) {
				values = append(values, name)
			}
		}
	}
	return DeduplicateSubdomains(values), nil
}

func (s CRTSource) Enumerate(ctx context.Context, domain string) ([]EnumResult, error) {
	normalizedDomain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	baseURL := s.BaseURL
	if baseURL == "" {
		baseURL = defaultCRTBaseURL
	}
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse crt.sh URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("q", "%."+normalizedDomain)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxBytes := s.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create crt.sh request: %w", err)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read crt.sh response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("crt.sh response exceeded size limit")
	}
	names, err := ParseCRTNames(body, normalizedDomain)
	if err != nil {
		return nil, err
	}
	results := make([]EnumResult, 0, len(names))
	for _, name := range names {
		results = append(results, EnumResult{Subdomain: name, Source: "crt.sh"})
	}
	return results, nil
}

type VTSource struct {
	APIKey   string
	BaseURL  string
	Client   *http.Client
	Timeout  time.Duration
	MaxBytes int64
}

func (s VTSource) Enumerate(ctx context.Context, domain string) ([]EnumResult, error) {
	if strings.TrimSpace(s.APIKey) == "" {
		return nil, &OptionalSourceError{Source: "virustotal", Message: "VT_API_KEY is not set; skipping VirusTotal"}
	}
	normalizedDomain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	baseURL := strings.TrimRight(s.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultVTBaseURL
	}
	endpoint := baseURL + "/domains/" + url.PathEscape(normalizedDomain) + "/subdomains"
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxBytes := s.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create VirusTotal request: %w", err)
	}
	req.Header.Set("x-apikey", s.APIKey)
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("VirusTotal returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read VirusTotal response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("VirusTotal response exceeded size limit")
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse VirusTotal JSON: %w", err)
	}
	results := make([]EnumResult, 0, len(payload.Data))
	for _, item := range payload.Data {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item.ID), "."))
		if name == normalizedDomain || strings.HasSuffix(name, "."+normalizedDomain) {
			results = append(results, EnumResult{Subdomain: name, Source: "virustotal"})
		}
	}
	return results, nil
}

type OptionalSourceError struct {
	Source  string
	Message string
}

func (e *OptionalSourceError) Error() string { return e.Source + ": " + e.Message }

type SourceError struct {
	Source   string
	Err      error
	Optional bool
}

func (e SourceError) Error() string { return e.Source + ": " + e.Err.Error() }

type Source interface {
	Enumerate(context.Context, string) ([]EnumResult, error)
}

type Enumerator struct {
	CRT Source
	VT  Source
	DNS *DNSBruteForcer
}

func (e Enumerator) Enumerate(ctx context.Context, domain string) ([]EnumResult, []SourceError) {
	results := make([]EnumResult, 0)
	errorsFound := make([]SourceError, 0)
	sources := []struct {
		name     string
		source   Source
		optional bool
	}{{name: "crt.sh", source: e.CRT}, {name: "virustotal", source: e.VT}}
	for _, source := range sources {
		if source.source == nil {
			continue
		}
		items, err := source.source.Enumerate(ctx, domain)
		if err != nil {
			optional := source.optional
			var optionalErr *OptionalSourceError
			if errors.As(err, &optionalErr) {
				optional = true
			}
			errorsFound = append(errorsFound, SourceError{Source: source.name, Err: err, Optional: optional})
			continue
		}
		results = append(results, items...)
	}
	if e.DNS != nil {
		items, err := e.DNS.Enumerate(ctx, domain)
		if err != nil {
			errorsFound = append(errorsFound, SourceError{Source: "dns-bruteforce", Err: err})
		} else {
			results = append(results, items...)
		}
	}
	return mergeResults(results), errorsFound
}

func mergeResults(results []EnumResult) []EnumResult {
	byName := make(map[string]EnumResult, len(results))
	for _, result := range results {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result.Subdomain), "."))
		if name == "" {
			continue
		}
		current, exists := byName[name]
		if !exists {
			result.Subdomain = name
			byName[name] = result
			continue
		}
		if current.IP == "" && result.IP != "" {
			current.IP = result.IP
		}
		if current.Source == "" {
			current.Source = result.Source
		} else if result.Source != "" && !strings.Contains(current.Source, result.Source) {
			current.Source += "," + result.Source
		}
		byName[name] = current
	}
	merged := make([]EnumResult, 0, len(byName))
	for _, result := range byName {
		merged = append(merged, result)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Subdomain < merged[j].Subdomain })
	return merged
}
