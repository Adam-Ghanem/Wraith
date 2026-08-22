package scan

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type fakeTCP struct{}

func (fakeTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	return httpengine.TCPResponse{Duration: time.Millisecond}, nil
}

func TestEngineUsesStandardProfileByDefault(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	result, err := e.Scan(context.Background(), "tcp://192.0.2.10/", Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Profile != npd.ProfileStandard {
		t.Fatalf("profile = %q, want %q", result.Profile, npd.ProfileStandard)
	}
	if len(result.Ports) != len(npd.DefaultPorts(npd.ProfileStandard)) {
		t.Fatalf("ports = %d, want %d", len(result.Ports), len(npd.DefaultPorts(npd.ProfileStandard)))
	}
}

func TestEngineRejectsDuplicatePorts(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	_, err := e.Scan(context.Background(), "tcp://192.0.2.10/", Options{Ports: []uint16{80, 80}})
	if err == nil {
		t.Fatal("Scan() error = nil, want duplicate-port error")
	}
}

func TestEngineRejectsRetryBudgetAboveBound(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	_, err := e.Scan(context.Background(), "tcp://192.0.2.10/", Options{Ports: []uint16{80}, MaxAttempts: MaxAttempts + 1})
	if err == nil {
		t.Fatal("Scan() error = nil, want retry-bound error")
	}
}

func TestEngineKeepsTargetNormalizationInNPD(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	result, err := e.Scan(context.Background(), "tcp://192.0.2.10/", Options{Ports: []uint16{443}})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	parsed, err := policy.ParseTarget(result.Target)
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	if parsed.Port != 0 || parsed.Scheme != string(policy.ProtocolTCP) {
		t.Fatalf("normalized target = %#v", parsed)
	}
}

func TestEngineCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := Engine{TCP: fakeTCP{}}
	result, err := e.Scan(ctx, "tcp://192.0.2.10/", Options{Ports: []uint16{80}})
	if err == nil {
		t.Fatal("Scan() error = nil, want cancellation")
	}
	if result.State != StateCancelled {
		t.Fatalf("state = %q, want %q", result.State, StateCancelled)
	}
	if result.CompletedAt.IsZero() {
		t.Fatal("CompletedAt is zero")
	}
}

func TestEngineTimeoutContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	e := Engine{TCP: fakeTCP{}}
	result, err := e.Scan(ctx, "tcp://192.0.2.10/", Options{Ports: []uint16{80}})
	if err == nil {
		t.Fatal("Scan() error = nil, want deadline exceeded")
	}
	if result.State != StateTimedOut {
		t.Fatalf("state = %q, want %q", result.State, StateTimedOut)
	}
}
