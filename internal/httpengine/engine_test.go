package httpengine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestDestinationPolicyRejectsPrivateMappedAndLinkLocalAddresses(t *testing.T) {
	t.Parallel()
	policy := DestinationPolicy{}
	for _, raw := range []string{"127.0.0.1", "169.254.1.1", "::1", "fe80::1", "::ffff:127.0.0.1"} {
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

type fakeObservationSink struct{ observation evidence.HTTPObservation }

func (sink *fakeObservationSink) AppendHTTP(_ context.Context, _ evidence.Endpoint, observation evidence.HTTPObservation) error {
	sink.observation = observation
	return nil
}

var _ = time.Second
