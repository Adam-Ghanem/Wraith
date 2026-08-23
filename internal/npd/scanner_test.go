package npd

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type fakeTCP struct {
	calls int
	err   error
}

func (f *fakeTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.calls++
	return httpengine.TCPResponse{Duration: time.Millisecond}, f.err
}

func TestParsePortsCanonicalAndBounded(t *testing.T) {
	ports, err := ParsePorts("443,22,80,8000-8002,80", 32)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 443, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestParsePortsFullTCPRange(t *testing.T) {
	ports, err := ParsePorts("1-65535", MaxPorts)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 65535 {
		t.Fatalf("got %d ports want 65535", len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("range endpoints=%d..%d", ports[0], ports[len(ports)-1])
	}
	for i, port := range ports {
		if int(port) != i+1 {
			t.Fatalf("ports[%d]=%d want %d", i, port, i+1)
		}
	}
}

func TestParsePortsOverlappingRangesDeduplicateBeforeLimit(t *testing.T) {
	ports, err := ParsePorts("1-3,3-5,1-5", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{1, 2, 3, 4, 5}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestParsePortsRejectsUnsafeInput(t *testing.T) {
	for _, spec := range []string{"0", "65536", "10-1", "-1", "1--2"} {
		if _, err := ParsePorts(spec, 4096); err == nil {
			t.Fatalf("ParsePorts(%q) unexpectedly succeeded", spec)
		}
	}
	if _, err := ParsePorts("1-4097", 4096); !errors.Is(err, ErrPortLimit) {
		t.Fatalf("error=%v want port limit", err)
	}
}

func TestScannerUsesOnlyR3TCPClient(t *testing.T) {
	fake := &fakeTCP{}
	scanner := Scanner{TCP: fake, Now: func() time.Time { return time.Unix(1, 0).UTC() }}
	plan, err := scanner.Plan("tcp://192.0.2.10", []uint16{443, 22, 80})
	if err != nil {
		t.Fatal(err)
	}
	plan.ProjectID = "project-a"
	plan.ScopeVersion = "scope-v1"
	result, err := scanner.Scan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 3 {
		t.Fatalf("R3 calls=%d want 3", fake.calls)
	}
	for i, port := range []uint16{22, 80, 443} {
		if result.Ports[i].Port != port || result.Ports[i].State != StateOpen {
			t.Fatalf("result[%d]=%#v", i, result.Ports[i])
		}
	}
	if result.Target != "tcp://192.0.2.10/" {
		t.Fatalf("target=%q", result.Target)
	}
}

func TestScannerConcurrencyIsBounded(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	fake := &boundedFakeTCP{active: &active, peak: &peak}
	scanner := Scanner{TCP: fake}
	ports := make([]uint16, 128)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	_, err := scanner.Scan(context.Background(), Scan{
		ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/",
		Ports: ports, Concurrency: MaxConcurrency + 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got > MaxConcurrency {
		t.Fatalf("peak concurrency=%d exceeds max=%d", got, MaxConcurrency)
	}
	if got := fake.calls.Load(); got != int32(len(ports)) {
		t.Fatalf("R3 calls=%d want %d", got, len(ports))
	}
}

type boundedFakeTCP struct {
	active *atomic.Int32
	peak   *atomic.Int32
	calls  atomic.Int32
}

func (f *boundedFakeTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.calls.Add(1)
	current := f.active.Add(1)
	for {
		previous := f.peak.Load()
		if current <= previous || f.peak.CompareAndSwap(previous, current) {
			break
		}
	}
	time.Sleep(1 * time.Millisecond)
	f.active.Add(-1)
	return httpengine.TCPResponse{Duration: time.Millisecond}, nil
}

func TestScannerDoesNotCallR3AfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeTCP{}
	scanner := Scanner{TCP: fake}
	_, err := scanner.Scan(ctx, Scan{ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/", Ports: []uint16{22}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want cancellation", err)
	}
	if fake.calls != 0 {
		t.Fatalf("R3 calls=%d want 0", fake.calls)
	}
}

func TestScannerNeverTreatsPolicyFailureAsClosed(t *testing.T) {
	fake := &fakeTCP{err: httpengine.ErrTCPPolicyDenied}
	scanner := Scanner{TCP: fake}
	result, err := scanner.Scan(context.Background(), Scan{ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "tcp://192.0.2.10/", Ports: []uint16{22}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ports[0].State == StateClosed || result.Ports[0].State != StatePolicy {
		t.Fatalf("state=%s", result.Ports[0].State)
	}
}

func TestScannerRejectsNonTCPTarget(t *testing.T) {
	fake := &fakeTCP{}
	scanner := Scanner{TCP: fake}
	for _, target := range []string{"https://example.test/", "example.test", "tcp://example.test:443"} {
		if _, err := scanner.Plan(target, []uint16{443}); err == nil {
			t.Fatalf("target %q unexpectedly accepted", target)
		}
	}
}
