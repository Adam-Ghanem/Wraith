package contentdiscovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type r75DenyGateway struct{ calls atomic.Int64 }

func (gateway *r75DenyGateway) Authorize(_ context.Context, _ string, _ policy.Target, _ policy.Action) (policy.Decision, error) {
	gateway.calls.Add(1)
	return policy.Decision{}, policy.ErrOutOfScope
}

type r75CountingResolver struct{ calls atomic.Int64 }

func (resolver *r75CountingResolver) Resolve(_ context.Context, _ string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

type r75AllowGateway struct{}

func (r75AllowGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action}, nil
}

func TestRunR75PolicyDenialPreventsDNSAndTargetIO(t *testing.T) {
	plan, err := BuildR75Plan("project-a", "https://example.test/", []string{"/admin"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	gateway := &r75DenyGateway{}
	resolver := &r75CountingResolver{}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: gateway, Resolver: resolver})
	_, err = RunR75(context.Background(), engine, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if !errors.Is(err, httpengine.ErrPolicyDenied) || gateway.calls.Load() != 1 || resolver.calls.Load() != 0 {
		t.Fatalf("err=%v policy_calls=%d resolver_calls=%d", err, gateway.calls.Load(), resolver.calls.Load())
	}
}

func TestRunR75LocalhostIntegrationUsesRealR3Engine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/admin":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte("admin portal"))
		default:
			writer.Header().Set("Content-Type", "text/html")
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte("missing"))
		}
	}))
	defer server.Close()
	plan, err := BuildR75Plan("project-a", server.URL, []string{"/admin", "/missing"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: r75AllowGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}})
	defer func() { _ = engine.CloseIdleConnections() }()
	run, err := RunR75(context.Background(), engine, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err != nil || len(run.Results) != 1 || run.Results[0].Path != "/admin" {
		t.Fatalf("run=%#v err=%v", run, err)
	}
}
