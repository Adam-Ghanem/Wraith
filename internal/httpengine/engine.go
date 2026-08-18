// Package httpengine is Wraith's shared, policy-aware HTTP(S) transport.
// It has no security-check, crawler, fuzzing, or scanner-specific behavior.
package httpengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

var (
	ErrInvalidRequest    = errors.New("invalid HTTP engine request")
	ErrPolicyDenied      = errors.New("HTTP request denied by policy")
	ErrDNSResolution     = errors.New("HTTP DNS resolution failed")
	ErrDestinationDenied = errors.New("HTTP destination denied by safety policy")
	ErrRedirectDenied    = errors.New("HTTP redirect denied")
	ErrRedirectLimit     = errors.New("HTTP redirect limit exceeded")
	ErrResponseTooLarge  = errors.New("HTTP response exceeded configured body limit")
	ErrObservation       = errors.New("HTTP observation emission failed")
)

type Request struct {
	ProjectID         string
	Method            string
	URL               string
	Headers           http.Header
	Body              []byte
	Timeout           time.Duration
	MaxResponseBytes  int64
	MaxRedirects      *int
	RetryPolicy       *RetryPolicy
	Source            string
	RedirectValidator func(currentURL, nextURL string) error
}

type Response struct {
	StatusCode    int
	Headers       http.Header
	ContentType   string
	ContentLength int64
	URL           string
	Redirects     []string
	Duration      time.Duration
	RemoteAddr    string
	Body          []byte
	Truncated     bool
}

// Resolver is injected for deterministic tests and controlled DNS behavior.
type Resolver interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
}

type ObservationSink interface {
	AppendHTTP(context.Context, evidence.Endpoint, evidence.HTTPObservation) error
}

type Config struct {
	Gateway               policy.OutboundTargetGateway
	Resolver              Resolver
	DestinationPolicy     DestinationPolicy
	ObservationSink       ObservationSink
	RateLimiter           *RateLimiter
	MaxConcurrentRequests int
	MaxResponseBytes      int64
	MaxRedirects          int
	RequestTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	UserAgent             string
	ProxyURL              string
	RetryPolicy           RetryPolicy
}

type Engine struct {
	config       Config
	transport    *http.Transport
	client       *http.Client
	destinations sync.Map
	proxyAddress string
	requestSlots chan struct{}
	configErr    error
}

func NewEngine(config Config) *Engine {
	if config.Resolver == nil {
		config.Resolver = netResolver{}
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 2 << 20
	}
	if config.MaxRedirects == 0 {
		config.MaxRedirects = 5
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.TLSHandshakeTimeout == 0 {
		config.TLSHandshakeTimeout = 5 * time.Second
	}
	if config.ResponseHeaderTimeout == 0 {
		config.ResponseHeaderTimeout = 5 * time.Second
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 30 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 32
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 4
	}
	if config.UserAgent == "" {
		config.UserAgent = "Wraith/http-engine"
	}
	if config.RetryPolicy.MaxAttempts == 0 {
		config.RetryPolicy = DefaultRetryPolicy()
	}
	if config.RateLimiter == nil {
		config.RateLimiter = NewRateLimiter(50 * time.Millisecond)
	}
	if config.MaxConcurrentRequests == 0 {
		config.MaxConcurrentRequests = 10
	}
	var configErr error
	if config.MaxConcurrentRequests < 1 || config.MaxConcurrentRequests > 50 {
		configErr = errors.New("invalid HTTP engine configuration")
		config.MaxConcurrentRequests = 1
	}
	engine := &Engine{config: config, requestSlots: make(chan struct{}, config.MaxConcurrentRequests), configErr: configErr}
	engine.transport = &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.TLSHandshakeTimeout, ResponseHeaderTimeout: config.ResponseHeaderTimeout, IdleConnTimeout: config.IdleConnTimeout, MaxIdleConns: config.MaxIdleConns, MaxIdleConnsPerHost: config.MaxIdleConnsPerHost}
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") || proxyURL.Host == "" {
			if engine.configErr == nil {
				engine.configErr = errors.New("invalid explicit proxy configuration")
			}
		} else {
			engine.transport.Proxy = http.ProxyURL(proxyURL)
			engine.proxyAddress = proxyDialAddress(proxyURL)
		}
	}
	engine.transport.DialContext = engine.dialContext
	engine.client = &http.Client{Transport: engine.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return engine
}

func (engine *Engine) CloseIdleConnections() error {
	if engine == nil || engine.transport == nil {
		return ErrInvalidRequest
	}
	engine.transport.CloseIdleConnections()
	return nil
}

func (engine *Engine) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if engine.proxyAddress != "" && address == engine.proxyAddress {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	mapped, exists := engine.destinations.Load(address)
	if !exists {
		return nil, ErrDestinationDenied
	}
	return (&net.Dialer{}).DialContext(ctx, network, mapped.(string))
}

func proxyDialAddress(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		if proxyURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

func targetHost(target policy.Target) string {
	if target.IP.IsValid() {
		return target.IP.String()
	}
	return target.Hostname
}

func (engine *Engine) Do(ctx context.Context, request Request) (Response, error) {
	if engine == nil || engine.config.Gateway == nil {
		return Response{}, fmt.Errorf("%w: missing policy gateway", ErrInvalidRequest)
	}
	if engine.configErr != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrInvalidRequest, engine.configErr)
	}
	if err := validateRequest(request, engine.config); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	if request.Source == "" {
		request.Source = "http-engine/manual"
	}
	retryPolicy := requestRetryPolicy(request, engine.config)
	for attempt := 1; attempt <= retryPolicy.MaxAttempts; attempt++ {
		response, err := engine.doWithRedirects(ctx, request)
		if attempt == retryPolicy.MaxAttempts || !retryPolicy.shouldRetry(response, err, request.Method) {
			return response, err
		}
		if err := waitRetry(ctx, retryPolicy.backoff(attempt)); err != nil {
			return response, err
		}
	}
	return Response{}, ErrInvalidRequest
}

func (engine *Engine) doWithRedirects(ctx context.Context, request Request) (Response, error) {
	current := request.URL
	redirects := make([]string, 0)
	maxRedirects := redirectLimit(request, engine.config)
	for hop := 0; ; hop++ {
		if hop > maxRedirects {
			return Response{Redirects: redirects}, ErrRedirectLimit
		}
		response, location, err := engine.doOne(ctx, request, current, redirects)
		if err != nil {
			if len(redirects) > 0 && errors.Is(err, ErrPolicyDenied) {
				return response, fmt.Errorf("%w: %v", ErrRedirectDenied, err)
			}
			return response, err
		}
		if location == "" {
			return response, nil
		}
		if hop == maxRedirects {
			return response, ErrRedirectLimit
		}
		next, err := responseURL(current, location)
		if err != nil {
			return response, fmt.Errorf("%w: %v", ErrRedirectDenied, err)
		}
		if request.RedirectValidator != nil {
			if err := request.RedirectValidator(current, next); err != nil {
				return response, fmt.Errorf("%w: %v", ErrRedirectDenied, err)
			}
		}
		redirects = append(redirects, next)
		current = next
	}
}

func (engine *Engine) doOne(parent context.Context, request Request, rawURL string, redirects []string) (Response, string, error) {
	target, err := policy.ParseTarget(rawURL)
	if err != nil {
		return Response{Redirects: redirects}, "", fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if _, err := engine.config.Gateway.Authorize(parent, request.ProjectID, target, policy.ActionHTTP); err != nil {
		return Response{Redirects: redirects}, "", fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if engine.config.RateLimiter != nil {
		if err := engine.config.RateLimiter.Wait(parent); err != nil {
			return Response{Redirects: redirects}, "", err
		}
	}
	if err := engine.acquireRequestSlot(parent); err != nil {
		return Response{Redirects: redirects}, "", err
	}
	defer engine.releaseRequestSlot()
	addresses, err := engine.resolveAndValidate(parent, request.ProjectID, target)
	if err != nil {
		return Response{Redirects: redirects}, "", err
	}
	ctx, cancel := context.WithTimeout(parent, timeoutFor(request, engine.config))
	defer cancel()
	dialKey := net.JoinHostPort(targetHost(target), fmt.Sprintf("%d", target.Port))
	engine.destinations.Store(dialKey, net.JoinHostPort(addresses[0].String(), fmt.Sprintf("%d", target.Port)))
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, rawURL, strings.NewReader(string(request.Body)))
	if err != nil {
		return Response{Redirects: redirects}, "", fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	httpRequest.Header = request.Headers.Clone()
	if httpRequest.Header == nil {
		httpRequest.Header = make(http.Header)
	}
	if httpRequest.Header.Get("User-Agent") == "" {
		httpRequest.Header.Set("User-Agent", engine.config.UserAgent)
	}
	started := time.Now()
	native, err := engine.client.Do(httpRequest)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Response{Redirects: redirects}, "", context.DeadlineExceeded
		}
		return Response{Redirects: redirects}, "", err
	}
	defer native.Body.Close()
	body, truncated, err := readBounded(native.Body, responseByteLimit(request, engine.config))
	if err != nil {
		return Response{Redirects: redirects}, "", err
	}
	response := Response{StatusCode: native.StatusCode, Headers: native.Header.Clone(), ContentType: native.Header.Get("Content-Type"), ContentLength: native.ContentLength, URL: rawURL, Redirects: redirects, Duration: time.Since(started), Body: body, Truncated: truncated}
	if response.ContentLength < 0 {
		response.ContentLength = int64(len(body))
	}
	if native.Body != nil {
		response.RemoteAddr = "validated:" + addresses[0].String()
	}
	if engine.config.ObservationSink != nil {
		endpoint, endpointErr := evidence.NewEndpoint(request.ProjectID, request.Method, rawURL, time.Now().UTC())
		if endpointErr != nil {
			return response, "", fmt.Errorf("%w: %v", ErrObservation, endpointErr)
		}
		observation, observationErr := evidence.NewHTTPObservation(request.ProjectID, endpoint, evidence.HTTPObservationInput{Source: request.Source, ObservedAt: time.Now().UTC(), StatusCode: response.StatusCode, ContentType: response.ContentType, ContentLength: response.ContentLength, Server: native.Header.Get("Server"), ResponseHeaders: headerMap(native.Header)})
		if observationErr != nil {
			return response, "", fmt.Errorf("%w: %v", ErrObservation, observationErr)
		}
		if err := engine.config.ObservationSink.AppendHTTP(parent, endpoint, observation); err != nil {
			return response, "", fmt.Errorf("%w: %v", ErrObservation, err)
		}
	}
	if native.StatusCode >= 300 && native.StatusCode <= 399 {
		return response, native.Header.Get("Location"), nil
	}
	return response, "", nil
}

func (engine *Engine) resolveAndValidate(ctx context.Context, projectID string, target policy.Target) ([]netip.Addr, error) {
	addresses := []netip.Addr{target.IP}
	if !target.IP.IsValid() {
		resolved, err := engine.config.Resolver.Resolve(ctx, target.Hostname)
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("%w: %v", ErrDNSResolution, err)
		}
		addresses = resolved
	}
	for _, address := range addresses {
		address = address.Unmap()
		if err := engine.config.DestinationPolicy.Validate(address); err != nil {
			return nil, err
		}
		resolvedTarget := policy.Target{IP: address, Port: target.Port}
		if _, err := engine.config.Gateway.Authorize(ctx, projectID, resolvedTarget, policy.ActionConnect); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
		}
	}
	return []netip.Addr{addresses[0].Unmap()}, nil
}

func validateRequest(request Request, config Config) error {
	if strings.TrimSpace(request.ProjectID) == "" || strings.TrimSpace(request.Method) == "" || strings.TrimSpace(request.URL) == "" || request.Timeout < 0 || request.MaxResponseBytes < 0 || request.MaxResponseBytes > 16<<20 || request.MaxRedirects != nil && (*request.MaxRedirects < 0 || *request.MaxRedirects > 10) || config.MaxConcurrentRequests < 1 || config.MaxConcurrentRequests > 50 || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 16<<20 || config.MaxRedirects < 0 || config.MaxRedirects > 10 || config.RequestTimeout <= 0 || config.IdleConnTimeout <= 0 || config.IdleConnTimeout > 5*time.Minute || config.MaxIdleConns < 1 || config.MaxIdleConns > 256 || config.MaxIdleConnsPerHost < 1 || config.MaxIdleConnsPerHost > config.MaxIdleConns {
		return errors.New("missing or out-of-bounds request configuration")
	}
	if err := config.RetryPolicy.validate(); err != nil {
		return err
	}
	if request.RetryPolicy != nil {
		return request.RetryPolicy.validate()
	}
	return nil
}

func requestRetryPolicy(request Request, config Config) RetryPolicy {
	if request.RetryPolicy != nil {
		return *request.RetryPolicy
	}
	return config.RetryPolicy
}

func responseByteLimit(request Request, config Config) int64 {
	if request.MaxResponseBytes > 0 {
		return request.MaxResponseBytes
	}
	return config.MaxResponseBytes
}

func redirectLimit(request Request, config Config) int {
	if request.MaxRedirects != nil {
		return *request.MaxRedirects
	}
	return config.MaxRedirects
}

func (engine *Engine) acquireRequestSlot(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case engine.requestSlots <- struct{}{}:
		return nil
	}
}

func (engine *Engine) releaseRequestSlot() {
	<-engine.requestSlots
}

func timeoutFor(request Request, config Config) time.Duration {
	if request.Timeout > 0 {
		return request.Timeout
	}
	return config.RequestTimeout
}
func responseURL(base, location string) (string, error) {
	source, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	next, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return source.ResolveReference(next).String(), nil
}
func readBounded(body io.Reader, maximum int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maximum {
		return data[:maximum], true, nil
	}
	return data, false, nil
}
func headerMap(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, ",")
	}
	return result
}

type netResolver struct{}

func (netResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type DestinationPolicy struct{ AllowPrivate bool }

var reservedDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func (policy DestinationPolicy) Validate(address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() {
		return ErrDestinationDenied
	}
	if !policy.AllowPrivate && (address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsPrivate() || isReservedDestination(address)) {
		return ErrDestinationDenied
	}
	return nil
}

func isReservedDestination(address netip.Addr) bool {
	for _, prefix := range reservedDestinationPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
