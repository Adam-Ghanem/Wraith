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
	ProjectID string
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
	Timeout   time.Duration
	Source    string
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
	MaxResponseBytes      int64
	MaxRedirects          int
	RequestTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	UserAgent             string
}

type Engine struct {
	config       Config
	transport    *http.Transport
	client       *http.Client
	destinations sync.Map
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
	if config.UserAgent == "" {
		config.UserAgent = "Wraith/http-engine"
	}
	engine := &Engine{config: config}
	engine.transport = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.TLSHandshakeTimeout, ResponseHeaderTimeout: config.ResponseHeaderTimeout, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 4}
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
	mapped, exists := engine.destinations.Load(address)
	if !exists {
		return nil, ErrDestinationDenied
	}
	return (&net.Dialer{}).DialContext(ctx, network, mapped.(string))
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
	current := request.URL
	redirects := make([]string, 0)
	for hop := 0; ; hop++ {
		if hop > engine.config.MaxRedirects {
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
		if hop == engine.config.MaxRedirects {
			return response, ErrRedirectLimit
		}
		next, err := responseURL(current, location)
		if err != nil {
			return response, fmt.Errorf("%w: %v", ErrRedirectDenied, err)
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
	body, truncated, err := readBounded(native.Body, engine.config.MaxResponseBytes)
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
	if strings.TrimSpace(request.ProjectID) == "" || strings.TrimSpace(request.Method) == "" || strings.TrimSpace(request.URL) == "" || request.Timeout < 0 || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 16<<20 || config.MaxRedirects < 0 || config.MaxRedirects > 10 || config.RequestTimeout <= 0 {
		return errors.New("missing or out-of-bounds request configuration")
	}
	return nil
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

func (policy DestinationPolicy) Validate(address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() {
		return ErrDestinationDenied
	}
	if !policy.AllowPrivate && (address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsPrivate() || address.Is4() && isCGNAT(address)) {
		return ErrDestinationDenied
	}
	return nil
}
func isCGNAT(address netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}
