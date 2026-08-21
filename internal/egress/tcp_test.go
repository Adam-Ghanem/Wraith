package egress

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type fakeTCPTransport struct {
	calls int
}

func (transport *fakeTCPTransport) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	transport.calls++
	return httpengine.TCPResponse{Duration: time.Millisecond}, nil
}

func TestTCPDispatcherRequiresT5Decision(t *testing.T) {
	transport := &fakeTCPTransport{}
	dispatcher := TCPDispatcher{Transport: transport}
	request := httpengine.TCPRequest{ProjectID: "project", Target: policy.Target{IP: mustAddr(t, "192.0.2.10"), Port: 443}, Timeout: time.Second}
	operation := outbound.Operation{ProjectID: "project", CapabilityID: "assessment-network-port-discovery"}

	_, err := dispatcher.DispatchTCP(context.Background(), outbound.Decision{}, operation, request)
	if err == nil {
		t.Fatal("expected denied dispatch")
	}
	if transport.calls != 0 {
		t.Fatalf("denied dispatch invoked transport %d times", transport.calls)
	}
}

func TestTCPDispatcherDelegatesOnlyAfterMatchingDecision(t *testing.T) {
	transport := &fakeTCPTransport{}
	dispatcher := TCPDispatcher{Transport: transport}
	request := httpengine.TCPRequest{ProjectID: "project", Target: policy.Target{IP: mustAddr(t, "192.0.2.10"), Port: 443}, Timeout: time.Second}
	operation := outbound.Operation{ProjectID: "project", CapabilityID: "assessment-network-port-discovery"}
	decision := outbound.Decision{
		Allowed:    true,
		Capability: outbound.Capability{ID: operation.CapabilityID, Operation: outbound.OperationTCP},
		Target:     request.Target,
	}

	if _, err := dispatcher.DispatchTCP(context.Background(), decision, operation, request); err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("expected exactly one transport call, got %d", transport.calls)
	}
}

func TestTCPDispatcherRejectsCapabilityTargetMismatch(t *testing.T) {
	transport := &fakeTCPTransport{}
	dispatcher := TCPDispatcher{Transport: transport}
	request := httpengine.TCPRequest{ProjectID: "project", Target: policy.Target{IP: mustAddr(t, "192.0.2.10"), Port: 443}, Timeout: time.Second}
	operation := outbound.Operation{ProjectID: "project", CapabilityID: "assessment-network-port-discovery"}
	decision := outbound.Decision{
		Allowed:    true,
		Capability: outbound.Capability{ID: operation.CapabilityID, Operation: outbound.OperationTCP},
		Target:     policy.Target{IP: request.Target.IP, Port: 22},
	}

	if _, err := dispatcher.DispatchTCP(context.Background(), decision, operation, request); err == nil {
		t.Fatal("expected capability mismatch")
	}
	if transport.calls != 0 {
		t.Fatalf("mismatched dispatch invoked transport %d times", transport.calls)
	}
}

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse address: %v", err)
	}
	return parsed
}
