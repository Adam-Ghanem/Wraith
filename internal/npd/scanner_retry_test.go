package npd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type sequenceTCP struct {
	mu       sync.Mutex
	errors   []error
	requests int
}

func (tcp *sequenceTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	tcp.requests++
	if len(tcp.errors) == 0 {
		return httpengine.TCPResponse{Duration: time.Millisecond}, nil
	}
	err := tcp.errors[0]
	tcp.errors = tcp.errors[1:]
	return httpengine.TCPResponse{Duration: time.Millisecond}, err
}

func TestScannerRetriesTransientTransportFailureOnce(t *testing.T) {
	tcp := &sequenceTCP{errors: []error{errors.New("temporary transport failure"), nil}}
	result, err := (Scanner{TCP: tcp}).Scan(context.Background(), Scan{ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Timeout: time.Second, Concurrency: 1, MaxAttempts: 2})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if tcp.requests != 2 {
		t.Fatalf("requests = %d, want 2", tcp.requests)
	}
	if result.Ports[0].State != StateOpen || result.Ports[0].AttemptCount != 2 {
		t.Fatalf("result = %#v", result.Ports[0])
	}
}

func TestScannerDoesNotRetryRefusedPort(t *testing.T) {
	tcp := &sequenceTCP{errors: []error{httpengine.ErrTCPRefused}}
	result, err := (Scanner{TCP: tcp}).Scan(context.Background(), Scan{ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Timeout: time.Second, Concurrency: 1, MaxAttempts: 3})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if tcp.requests != 1 || result.Ports[0].State != StateClosed || result.Ports[0].AttemptCount != 1 {
		t.Fatalf("result = %#v requests=%d", result.Ports[0], tcp.requests)
	}
}

type cancellingTCP struct {
	cancel   context.CancelFunc
	requests int
}

func (tcp *cancellingTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	tcp.requests++
	tcp.cancel()
	return httpengine.TCPResponse{}, errors.New("temporary transport failure")
}

func TestScannerStopsRetriesAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tcp := &cancellingTCP{cancel: cancel}
	result, err := (Scanner{TCP: tcp}).Scan(ctx, Scan{ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Timeout: time.Second, Concurrency: 1, MaxAttempts: 3})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	if tcp.requests != 1 || result.Ports[0].AttemptCount != 1 || result.Ports[0].State != StateCancelled {
		t.Fatalf("result = %#v requests=%d", result.Ports[0], tcp.requests)
	}
}
