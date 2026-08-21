package httpengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestProbeTCPLoopbackOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	response, err := engine.ProbeTCP(context.Background(), TCPRequest{ProjectID: "project-a", Target: policy.Target{IP: netip.MustParseAddr("127.0.0.1"), Port: port}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("ProbeTCP: %v", err)
	}
	if response.RemoteAddr == "" {
		t.Fatal("ProbeTCP returned empty remote address")
	}
}

func TestProbeTCPRefusedIsTyped(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()

	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err = engine.ProbeTCP(context.Background(), TCPRequest{ProjectID: "project-a", Target: policy.Target{IP: netip.MustParseAddr("127.0.0.1"), Port: port}, Timeout: 250 * time.Millisecond})
	if !errors.Is(err, ErrTCPRefused) {
		t.Fatalf("error=%v, want ErrTCPRefused", err)
	}
}

func TestProbeTCPPolicyDeniesBeforeNetworkIO(t *testing.T) {
	engine := NewEngine(Config{Gateway: fakeGateway{deny: true}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err := engine.ProbeTCP(context.Background(), TCPRequest{ProjectID: "project-a", Target: policy.Target{IP: netip.MustParseAddr("127.0.0.1"), Port: 1}, Timeout: time.Second})
	if !errors.Is(err, ErrTCPPolicyDenied) {
		t.Fatalf("error=%v, want ErrTCPPolicyDenied", err)
	}
}

func TestProbeTCPHonorsCancellationBeforeNetworkIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	_, err := engine.ProbeTCP(ctx, TCPRequest{ProjectID: "project-a", Target: policy.Target{IP: netip.MustParseAddr("127.0.0.1"), Port: 1}, Timeout: time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context.Canceled", err)
	}
}
