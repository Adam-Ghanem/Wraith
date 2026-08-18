package crawler

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

var ErrInvalidConfig = errors.New("invalid crawler configuration")

type Config struct {
	ProjectID                                            string
	StartURLs                                            []string
	MaxDepth, MaxPages, MaxConcurrency, MaxQueryVariants int
	MaxResponseBytes, MaxTotalBytes                      int64
	Timeout, MaxDuration                                 time.Duration
	MaxRedirects                                         int
	SameOrigin, AllowSubdomains, RespectRobots           bool
	Include, Exclude                                     []string
	UserAgent                                            string
	Headers                                              http.Header
}

type URLResult struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}
type Error struct {
	URL     string `json:"url"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}
type Result struct {
	PagesDiscovered  int           `json:"pages_discovered"`
	PagesFetched     int           `json:"pages_fetched"`
	Endpoints        int           `json:"endpoints"`
	Parameters       int           `json:"parameters"`
	Forms            int           `json:"forms"`
	JavaScriptAssets int           `json:"javascript_assets"`
	APIReferences    int           `json:"api_references"`
	Redirects        int           `json:"redirects"`
	Errors           []Error       `json:"errors,omitempty"`
	Duration         time.Duration `json:"duration"`
}

type Crawler struct {
	Client     httpengine.Client
	Repository evidence.Repository
}
type frontierItem struct {
	URL   string
	Depth int
}

func DefaultConfig(projectID, startURL string) Config {
	return Config{ProjectID: projectID, StartURLs: []string{startURL}, MaxDepth: 2, MaxPages: 100, MaxConcurrency: 4, MaxQueryVariants: 20, MaxResponseBytes: 1 << 20, MaxTotalBytes: 16 << 20, Timeout: 10 * time.Second, MaxDuration: 2 * time.Minute, MaxRedirects: 5, SameOrigin: true, RespectRobots: true, UserAgent: "Wraith/crawler"}
}

func (crawler Crawler) Crawl(ctx context.Context, config Config) (Result, error) {
	started := time.Now()
	if crawler.Client == nil || !validConfig(config) {
		return Result{}, ErrInvalidConfig
	}
	ctx, cancel := context.WithTimeout(ctx, config.MaxDuration)
	defer cancel()
	start, err := evidence.CanonicalizeURL(config.StartURLs[0])
	if err != nil {
		return Result{}, err
	}
	startURL, _ := url.Parse(start.String())
	queue, seen, queryVariants := []frontierItem{}, map[string]struct{}{}, map[string]int{}
	enqueue := func(raw string, depth int) {
		if depth > config.MaxDepth || len(seen) >= config.MaxPages || !crawler.allowed(raw, startURL, config) {
			return
		}
		canonical, err := evidence.CanonicalizeURL(raw)
		if err != nil {
			return
		}
		identity := canonical.String()
		if _, exists := seen[identity]; exists {
			return
		}
		parsed, parseErr := url.Parse(identity)
		if parseErr != nil {
			return
		}
		variantKey := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if parsed.RawQuery != "" {
			if queryVariants[variantKey] >= config.MaxQueryVariants {
				return
			}
			queryVariants[variantKey]++
		}
		seen[identity] = struct{}{}
		queue = append(queue, frontierItem{URL: identity, Depth: depth})
	}
	for _, raw := range config.StartURLs {
		enqueue(raw, 0)
	}
	result := Result{PagesDiscovered: len(queue)}
	var totalBytes int64
	robots := robotRules{}
	if config.RespectRobots {
		robots = crawler.fetchRobots(ctx, config, startURL, &result)
		sitemaps := robots.Sitemaps
		if len(sitemaps) == 0 {
			sitemaps = []string{startURL.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String()}
		}
		for _, sitemap := range sitemaps {
			if !crawler.allowed(sitemap, startURL, config) {
				continue
			}
			for _, item := range crawler.fetchSitemap(ctx, config, sitemap, &result) {
				enqueue(item, 1)
			}
		}
	}
	for len(queue) > 0 && result.PagesFetched < config.MaxPages {
		if err := ctx.Err(); err != nil {
			result.Duration = time.Since(started)
			return result, err
		}
		item := queue[0]
		queue = queue[1:]
		if config.RespectRobots && robots.disallowed(item.URL, startURL.Path) {
			continue
		}
		response, err := crawler.Client.Do(ctx, httpengine.Request{ProjectID: config.ProjectID, Method: http.MethodGet, URL: item.URL, Headers: config.Headers, Timeout: config.Timeout, MaxResponseBytes: config.MaxResponseBytes, MaxRedirects: &config.MaxRedirects, Source: "crawler"})
		if err != nil {
			result.Errors = append(result.Errors, Error{URL: item.URL, Kind: errorKind(err), Message: "request failed"})
			continue
		}
		result.PagesFetched++
		result.Redirects += len(response.Redirects)
		totalBytes += int64(len(response.Body))
		if totalBytes > config.MaxTotalBytes {
			result.Errors = append(result.Errors, Error{URL: item.URL, Kind: "limit", Message: "total crawl byte limit reached"})
			break
		}
		crawler.persist(ctx, config.ProjectID, item.URL, "GET", evidence.AssetKindURL, evidence.ParameterLocationQuery, &result)
		if isHTML(response.ContentType) {
			document, parseErr := ExtractDocument(item.URL, response.Body)
			if parseErr != nil {
				result.Errors = append(result.Errors, Error{URL: item.URL, Kind: "parse", Message: "HTML parse failed"})
				continue
			}
			result.Forms += len(document.Forms)
			result.JavaScriptAssets += len(document.JavaScript)
			result.APIReferences += len(document.APIReferences)
			for _, discovered := range document.URLs {
				enqueue(discovered, item.Depth+1)
			}
			for _, script := range document.JavaScript {
				crawler.persist(ctx, config.ProjectID, script, "GET", evidence.AssetKindJavaScript, evidence.ParameterLocationQuery, &result)
			}
			for _, form := range document.Forms {
				crawler.persist(ctx, config.ProjectID, form.Action, form.Method, evidence.AssetKindURL, evidence.ParameterLocationBody, &result)
				for _, name := range form.Parameters {
					crawler.persistParameter(ctx, config.ProjectID, form.Action, form.Method, evidence.ParameterLocationBody, name, &result)
				}
				for _, discovered := range []string{form.Action} {
					enqueue(discovered, item.Depth+1)
				}
			}
			for _, api := range document.APIReferences {
				crawler.persist(ctx, config.ProjectID, api, "GET", evidence.AssetKindURL, evidence.ParameterLocationQuery, &result)
			}
		}
		result.PagesDiscovered = len(seen)
	}
	crawler.fetchSecurityTXT(ctx, config, startURL, &result)
	result.Duration = time.Since(started)
	return result, nil
}

func validConfig(c Config) bool {
	return strings.TrimSpace(c.ProjectID) != "" && len(c.StartURLs) > 0 && c.MaxDepth >= 0 && c.MaxDepth <= 10 && c.MaxPages > 0 && c.MaxPages <= 10000 && c.MaxConcurrency > 0 && c.MaxConcurrency <= 50 && c.MaxQueryVariants > 0 && c.MaxQueryVariants <= 100 && c.MaxResponseBytes > 0 && c.MaxResponseBytes <= 16<<20 && c.MaxTotalBytes >= c.MaxResponseBytes && c.MaxTotalBytes <= 256<<20 && c.Timeout > 0 && c.Timeout <= 30*time.Second && c.MaxDuration > 0 && c.MaxDuration <= 30*time.Minute && c.MaxRedirects >= 0 && c.MaxRedirects <= 10
}
func (c Crawler) allowed(raw string, start *url.URL, config Config) bool {
	candidate, err := url.Parse(raw)
	if err != nil || (candidate.Scheme != "http" && candidate.Scheme != "https") || candidate.User != nil {
		return false
	}
	if config.SameOrigin && !sameOrigin(candidate, start, config.AllowSubdomains) {
		return false
	}
	for _, pattern := range config.Exclude {
		if strings.Contains(candidate.String(), pattern) {
			return false
		}
	}
	if len(config.Include) > 0 {
		allowed := false
		for _, pattern := range config.Include {
			if strings.Contains(candidate.String(), pattern) {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}
func sameOrigin(candidate, start *url.URL, subdomains bool) bool {
	if candidate.Scheme != start.Scheme {
		return false
	}
	if strings.EqualFold(candidate.Hostname(), start.Hostname()) {
		return candidate.Port() == start.Port()
	}
	return subdomains && strings.HasSuffix(strings.ToLower(candidate.Hostname()), "."+strings.ToLower(start.Hostname()))
}
func isHTML(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml")
}
func errorKind(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancellation"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, httpengine.ErrPolicyDenied) || errors.Is(err, httpengine.ErrRedirectDenied) {
		return "policy"
	}
	if errors.Is(err, httpengine.ErrDNSResolution) {
		return "dns"
	}
	return "http"
}
func (c Crawler) persist(ctx context.Context, projectID, rawURL, method string, kind evidence.AssetKind, location evidence.ParameterLocation, result *Result) {
	if c.Repository == nil {
		return
	}
	now := time.Now().UTC()
	asset, err := evidence.NewWebAsset(projectID, kind, rawURL, now)
	if err == nil {
		_, _ = c.Repository.UpsertWebAsset(ctx, asset)
	}
	endpoint, err := evidence.NewEndpoint(projectID, method, rawURL, now)
	if err == nil {
		_, _ = c.Repository.UpsertEndpoint(ctx, endpoint)
		result.Endpoints++
		query, _ := url.Parse(rawURL)
		for name := range query.Query() {
			c.persistParameter(ctx, projectID, rawURL, method, evidence.ParameterLocationQuery, name, result)
		}
	}
}
func (c Crawler) persistParameter(ctx context.Context, projectID, rawURL, method string, location evidence.ParameterLocation, name string, result *Result) {
	if c.Repository == nil {
		return
	}
	endpoint, err := evidence.NewEndpoint(projectID, method, rawURL, time.Now().UTC())
	if err != nil {
		return
	}
	parameter, err := evidence.NewParameter(projectID, endpoint, location, name, time.Now().UTC())
	if err == nil {
		_, _ = c.Repository.UpsertParameter(ctx, parameter)
		result.Parameters++
	}
}

type robotRules struct{ Disallow, Sitemaps []string }

func (c Crawler) fetchRobots(ctx context.Context, cfg Config, start *url.URL, result *Result) robotRules {
	raw := start.ResolveReference(&url.URL{Path: "/robots.txt"}).String()
	response, err := c.Client.Do(ctx, httpengine.Request{ProjectID: cfg.ProjectID, Method: http.MethodGet, URL: raw, Headers: cfg.Headers, Timeout: cfg.Timeout, MaxResponseBytes: 64 << 10, MaxRedirects: &cfg.MaxRedirects, Source: "crawler.robots"})
	if err != nil {
		return robotRules{}
	}
	rules := robotRules{}
	for _, line := range strings.Split(string(response.Body), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "disallow":
			if strings.TrimSpace(value) != "" {
				rules.Disallow = append(rules.Disallow, strings.TrimSpace(value))
			}
		case "sitemap":
			if resolved, ok := resolveCanonical(start, strings.TrimSpace(value)); ok {
				rules.Sitemaps = append(rules.Sitemaps, resolved)
			}
		}
	}
	return rules
}
func (r robotRules) disallowed(raw, _ string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	for _, prefix := range r.Disallow {
		if strings.HasPrefix(parsed.Path, prefix) {
			return true
		}
	}
	return false
}
func (c Crawler) fetchSitemap(ctx context.Context, cfg Config, raw string, result *Result) []string {
	response, err := c.Client.Do(ctx, httpengine.Request{ProjectID: cfg.ProjectID, Method: http.MethodGet, URL: raw, Headers: cfg.Headers, Timeout: cfg.Timeout, MaxResponseBytes: 512 << 10, MaxRedirects: &cfg.MaxRedirects, Source: "crawler.sitemap"})
	if err != nil {
		return nil
	}
	var doc struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
		Maps []struct {
			Loc string `xml:"loc"`
		} `xml:"sitemap"`
	}
	if xml.Unmarshal(response.Body, &doc) != nil {
		return nil
	}
	urls := make([]string, 0, len(doc.URLs)+len(doc.Maps))
	for _, entry := range doc.URLs {
		urls = append(urls, entry.Loc)
	}
	for _, entry := range doc.Maps {
		urls = append(urls, entry.Loc)
	}
	return urls
}
func (c Crawler) fetchSecurityTXT(ctx context.Context, cfg Config, start *url.URL, result *Result) {
	raw := start.ResolveReference(&url.URL{Path: "/.well-known/security.txt"}).String()
	response, err := c.Client.Do(ctx, httpengine.Request{ProjectID: cfg.ProjectID, Method: http.MethodGet, URL: raw, Headers: cfg.Headers, Timeout: cfg.Timeout, MaxResponseBytes: 64 << 10, MaxRedirects: &cfg.MaxRedirects, Source: "crawler.securitytxt"})
	if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
		c.persist(ctx, cfg.ProjectID, raw, "GET", evidence.AssetKindURL, evidence.ParameterLocationQuery, result)
	}
}

var _ = path.Clean
