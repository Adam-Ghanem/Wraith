package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

type fakeTCP struct {
	calls int
	err   error
}

func (f *fakeTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.calls++
	return httpengine.TCPResponse{Duration: time.Millisecond}, f.err
}

func TestEngineRunsNPDDiscoveryThroughInjectedTransport(t *testing.T) {
	fake := &fakeTCP{}
	engine := Engine{TCP: fake, Now: func() time.Time { return time.Unix(100, 0).UTC() }}
	result, err := engine.Run(context.Background(), Request{
		ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/",
		Profile: ProfileCustom, Ports: []uint16{443, 22, 80}, Timeout: time.Second, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 3 {
		t.Fatalf("R3 calls=%d want 3", fake.calls)
	}
	if len(result.Ports) != 3 {
		t.Fatalf("ports=%d want 3", len(result.Ports))
	}
	for i, port := range []uint16{22, 80, 443} {
		if result.Ports[i].Port != port || result.Ports[i].State != npd.StateOpen {
			t.Fatalf("result[%d]=%#v", i, result.Ports[i])
		}
	}
	if result.Target != "tcp://192.0.2.10/" {
		t.Fatalf("target=%q", result.Target)
	}
}

func TestEnginePreservesPolicyFailureAsStructuredState(t *testing.T) {
	fake := &fakeTCP{err: httpengine.ErrTCPPolicyDenied}
	engine := Engine{TCP: fake}
	result, err := engine.Run(context.Background(), Request{
		ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/",
		Profile: ProfileCustom, Ports: []uint16{22}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ports[0].State != npd.StatePolicy {
		t.Fatalf("state=%s want %s", result.Ports[0].State, npd.StatePolicy)
	}
}

func TestEngineRejectsInvalidProfileAndPortConfiguration(t *testing.T) {
	engine := Engine{TCP: &fakeTCP{}}
	cases := []Request{
		{ProjectID: "p", ScopeVersion: "s", Target: "tcp://192.0.2.10/", Profile: "unknown"},
		{ProjectID: "p", ScopeVersion: "s", Target: "tcp://192.0.2.10/", Profile: ProfileCustom},
		{ProjectID: "p", ScopeVersion: "s", Target: "tcp://192.0.2.10/", Profile: ProfileStandard, Ports: []uint16{22}},
	}
	for _, tc := range cases {
		if _, err := engine.Run(context.Background(), tc); err == nil {
			t.Fatalf("request unexpectedly succeeded: %#v", tc)
		}
	}
}

func TestEngineStopsBeforeTransportOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeTCP{}
	engine := Engine{TCP: fake}
	_, err := engine.Run(ctx, Request{
		ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/",
		Profile: ProfileCustom, Ports: []uint16{22}, Timeout: time.Second,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want cancellation", err)
	}
	if fake.calls != 0 {
		t.Fatalf("transport calls=%d want 0", fake.calls)
	}
}
