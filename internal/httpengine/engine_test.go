package httpengine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestEngineDeniesBeforeDNSOrNetworkIO(t *testing.T) {
	t.Parallel()
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	engine := NewEngine(Config{Resolver: resolver, Gateway: fakeGateway{deny: true}})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: "http://example.com/"})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("error = %v, want ErrPolicyDenied", err)
	}
	if resolver.calls.Load() != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolver.calls.Load())
	}
}

func TestEngineHonorsCanceledContextBeforeDNSOrNetworkIO(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	engine := NewEngine(Config{Resolver: resolver, Gateway: fakeGateway{}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := engine.Do(ctx, Request{ProjectID: "project-a", Method: http.MethodGet, URL: "http://example.com/"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context.Canceled", err)
	}
	if resolver.calls.Load() != 0 {
		t.Fatalf("resolver calls=%d, want zero after cancellation", resolver.calls.Load())
	}
}

func TestEngineUsesValidatedDestinationBoundsBodyAndEmitsRedactedObservation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Authorization", "opaque")
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("abcdef"))
	}))
	defer server.Close()
	address := netip.MustParseAddr("127.0.0.1")
	sink := &fakeObservationSink{}
	engine := NewEngine(Config{Gateway: fakeGateway{}, Resolver: &fakeResolver{addresses: []netip.Addr{address}}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, MaxResponseBytes: 3, ObservationSink: sink})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL, Source: "http-engine/manual"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(response.Body) != "abc" || !response.Truncated {
		t.Fatalf("response = %#v, want truncated first three bytes", response)
	}
	if sink.observation.ResponseHeaders["authorization"] != "REDACTED" || !sink.observation.Redacted {
		t.Fatalf("observation redaction = %#v", sink.observation)
	}
}

func TestEngineHonorsPerRequestResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("abcdef"))
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, MaxResponseBytes: 6})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL, MaxResponseBytes: 3})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(response.Body) != "abc" || !response.Truncated {
		t.Fatalf("response=%#v, want per-request bound of three bytes", response)
	}
}

func TestEngineAppliesValidatedHostOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "admin.example.test" {
			writer.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL, HostOverride: "admin.example.test"})
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestEngineDeniesHostOverrideBeforeDNSOrNetworkIO(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	engine := NewEngine(Config{Gateway: fakeGateway{deniedHost: "admin.example.test"}, Resolver: resolver})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: "https://example.test/", HostOverride: "admin.example.test"})
	if !errors.Is(err, ErrPolicyDenied) || resolver.calls.Load() != 0 {
		t.Fatalf("err=%v resolver_calls=%d", err, resolver.calls.Load())
	}
}

func TestEngineSendsPOSTCustomHeadersCookiesAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-Wraith-Trace") != "trace-a" || request.Header.Get("Cookie") != "session=opaque" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != "payload" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodPost, URL: server.URL, Headers: http.Header{"X-Wraith-Trace": []string{"trace-a"}, "Cookie": []string{"session=opaque"}}, Body: []byte("payload")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d, want 201", response.StatusCode)
	}
}

func TestEngineRejectsUntrustedTLSCertificateByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL})
	if err == nil {
		t.Fatal("Do succeeded with an untrusted TLS certificate")
	}
}

func TestEngineHandlesAuthorizedIPv6Literal(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if response.StatusCode != http.StatusNoContent || !strings.Contains(response.RemoteAddr, "::1") {
		t.Fatalf("response=%#v, want a validated IPv6 destination", response)
	}
}

func TestEngineReauthorizesRedirectBeforeResolvingRedirectTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://denied.example/", http.StatusFound)
	}))
	defer server.Close()
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	engine := NewEngine(Config{Gateway: fakeGateway{deniedHost: "denied.example"}, Resolver: resolver, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL})
	if !errors.Is(err, ErrRedirectDenied) {
		t.Fatalf("error = %v, want ErrRedirectDenied", err)
	}
	if resolver.calls.Load() != 0 {
		t.Fatalf("resolver calls = %d, want 0: IP-literal fixture and denied redirect target must not resolve", resolver.calls.Load())
	}
}

func TestEngineAppliesPerRequestRedirectValidatorBeforeFollowingTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://outside.example.invalid/", http.StatusFound)
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err := engine.Do(context.Background(), Request{
		ProjectID: "project-a",
		Method:    http.MethodGet,
		URL:       server.URL,
		RedirectValidator: func(_, _ string) error {
			return errors.New("redirect target outside authorized hostname boundary")
		},
	})
	if !errors.Is(err, ErrRedirectDenied) || !strings.Contains(err.Error(), "authorized hostname") {
		t.Fatalf("error = %v, want redirect validator denial", err)
	}
}

func TestDestinationPolicyRejectsPrivateMappedAndLinkLocalAddresses(t *testing.T) {
	t.Parallel()
	policy := DestinationPolicy{}
	for _, raw := range []string{"127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"} {
		if err := policy.Validate(netip.MustParseAddr(raw)); !errors.Is(err, ErrDestinationDenied) {
			t.Errorf("Validate(%s) = %v, want ErrDestinationDenied", raw, err)
		}
	}
}

func TestEngineReusesIdleConnectionAcrossSeparateCalls(t *testing.T) {
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL}); err != nil {
			t.Fatalf("request %d: %v", attempt+1, err)
		}
	}
	if newConnections.Load() != 1 {
		t.Fatalf("new connections = %d, want one reusable idle connection", newConnections.Load())
	}
	if err := engine.CloseIdleConnections(); err != nil {
		t.Fatalf("CloseIdleConnections: %v", err)
	}
}

func TestEngineHonorsConfiguredConnectionPoolLimits(t *testing.T) {
	engine := NewEngine(Config{Gateway: fakeGateway{}, IdleConnTimeout: 7 * time.Second, MaxIdleConns: 12, MaxIdleConnsPerHost: 3})
	if engine.transport.IdleConnTimeout != 7*time.Second || engine.transport.MaxIdleConns != 12 || engine.transport.MaxIdleConnsPerHost != 3 {
		t.Fatalf("transport pool=%+v, want configured idle lifecycle limits", engine.transport)
	}
}

func TestEngineRejectsInvalidConcurrencyConfigurationWithoutPanic(t *testing.T) {
	engine := NewEngine(Config{Gateway: fakeGateway{}, MaxConcurrentRequests: -1})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: "https://example.com/"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v, want ErrInvalidRequest", err)
	}
}

func TestEngineUsesExplicitProxyWithoutBypassingTargetAuthorization(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proxyHits.Add(1)
		if request.Header.Get("Proxy-Authorization") != "Basic cHJveHk6c2VjcmV0" {
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, ProxyURL: "http://proxy:secret@" + strings.TrimPrefix(proxy.URL, "http://")})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: target.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if response.StatusCode != http.StatusNoContent || proxyHits.Load() != 1 || targetHits.Load() != 0 {
		t.Fatalf("status=%d proxyHits=%d targetHits=%d, want proxied response without a direct target connection", response.StatusCode, proxyHits.Load(), targetHits.Load())
	}
}

func TestEngineDeniesUnauthorizedTargetBeforeProxyConnection(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{deny: true}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, ProxyURL: proxy.URL})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: "https://example.com/"})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("error=%v, want ErrPolicyDenied", err)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("proxy hits=%d, want zero before target authorization", proxyHits.Load())
	}
}

func TestEngineRejectsInvalidExplicitProxyConfiguration(t *testing.T) {
	engine := NewEngine(Config{Gateway: fakeGateway{}, ProxyURL: "socks5://proxy.example.invalid:1080"})
	_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: "https://example.com/"})
	if !errors.Is(err, ErrInvalidRequest) || strings.Contains(err.Error(), "proxy.example.invalid") {
		t.Fatalf("error=%v, want redacted invalid proxy configuration", err)
	}
}

func TestLocalRateLimiterRespectsContextCancellation(t *testing.T) {
	limiter := NewRateLimiter(10 * time.Second)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Wait error = %v, want context.Canceled", err)
	}
}

func TestLocalRateLimiterRejectsInvalidInterval(t *testing.T) {
	if err := NewRateLimiter(0).Wait(context.Background()); err == nil {
		t.Fatal("zero interval limiter allowed a request instead of failing closed")
	}
}

func TestEngineBoundsConcurrentRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, MaxConcurrentRequests: 2})
	errorsFound := make(chan error, 6)
	for request := 0; request < 6; request++ {
		go func() {
			_, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL})
			errorsFound <- err
		}()
	}
	<-entered
	<-entered
	close(release)
	for request := 0; request < 6; request++ {
		if err := <-errorsFound; err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum active requests=%d, want at most two", maximum.Load())
	}
}

func TestRetryPolicyDefaultsToIdempotentMethodsOnly(t *testing.T) {
	policy := DefaultRetryPolicy()
	if !policy.ShouldRetryMethod(http.MethodGet) || !policy.ShouldRetryMethod(http.MethodHead) {
		t.Fatal("default retry policy must permit idempotent reads")
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if policy.ShouldRetryMethod(method) {
			t.Fatalf("default retry policy must not retry %s", method)
		}
	}
}

func TestEngineRetriesConfiguredSafeReadWithReauthorization(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	gateway := &countingGateway{}
	engine := NewEngine(Config{
		Gateway:           gateway,
		DestinationPolicy: DestinationPolicy{AllowPrivate: true},
		RetryPolicy: RetryPolicy{
			MaxAttempts:          2,
			InitialBackoff:       time.Millisecond,
			MaxBackoff:           time.Millisecond,
			RetryableStatusCodes: []int{http.StatusServiceUnavailable},
		},
	})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if response.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("response=%#v calls=%d, want one retry and 200", response, calls.Load())
	}
	if gateway.calls.Load() < 4 {
		t.Fatalf("gateway calls=%d, want HTTP and connect authorization for each attempt", gateway.calls.Load())
	}
}

func TestEngineDoesNotRetryPOSTByDefault(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}, RetryPolicy: RetryPolicy{MaxAttempts: 2, RetryableStatusCodes: []int{http.StatusServiceUnavailable}}})
	response, err := engine.Do(context.Background(), Request{ProjectID: "project-a", Method: http.MethodPost, URL: server.URL, Body: []byte("stateful")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d, want one non-replayed POST", response.StatusCode, calls.Load())
	}
}

type fakeResolver struct {
	addresses []netip.Addr
	calls     atomic.Int32
}

func (resolver *fakeResolver) Resolve(_ context.Context, _ string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return append([]netip.Addr(nil), resolver.addresses...), nil
}

type fakeGateway struct {
	deny       bool
	deniedHost string
}

func (gateway fakeGateway) Authorize(_ context.Context, projectID string, target policy.Target, _ policy.Action) (policy.Decision, error) {
	decision := policy.Decision{ProjectID: projectID, Target: target}
	if gateway.deny || gateway.deniedHost != "" && target.Hostname == gateway.deniedHost {
		return decision, policy.ErrOutOfScope
	}
	decision.Allowed = true
	return decision, nil
}

type countingGateway struct{ calls atomic.Int32 }

func (gateway *countingGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	gateway.calls.Add(1)
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action}, nil
}

type fakeObservationSink struct{ observation evidence.HTTPObservation }

func (sink *fakeObservationSink) AppendHTTP(_ context.Context, _ evidence.Endpoint, observation evidence.HTTPObservation) error {
	sink.observation = observation
	return nil
}

var _ = time.Second
