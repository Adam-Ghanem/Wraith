package scan

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type dualSYNTransport struct {
	v4Calls int
	v6Calls int
	v4Err   error
}

func (f *dualSYNTransport) ScanSYN(_ context.Context, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	f.v4Calls++
	if f.v4Err != nil {
		return nil, f.v4Err
	}
	return []httpengine.SYNResponse{{Port: request.Ports[0], State: httpengine.SYNStateOpen, ObservedAt: time.Now().UTC()}}, nil
}

func (f *dualSYNTransport) ScanSYN6(_ context.Context, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	f.v6Calls++
	return []httpengine.SYNResponse{{Port: request.Ports[0], State: httpengine.SYNStateOpen, ObservedAt: time.Now().UTC(), TTL: 61}}, nil
}

func TestExecuteSYNUsesIPv6TransportForIPv6Target(t *testing.T) {
	transport := &dualSYNTransport{}
	engine := Engine{SYN: transport}
	target := policy.Target{IP: netip.MustParseAddr("2001:db8::10")}
	request := httpengine.SYNScanRequest{ProjectID: "test", Target: target, Ports: []uint16{443}, Timeout: time.Second}
	observations, err := engine.executeSYN(context.Background(), target, request)
	if err != nil {
		t.Fatal(err)
	}
	if transport.v4Calls != 0 || transport.v6Calls != 1 {
		t.Fatalf("v4Calls=%d v6Calls=%d, want 0/1", transport.v4Calls, transport.v6Calls)
	}
	if len(observations) != 1 || observations[0].Port != 443 {
		t.Fatalf("unexpected observations: %#v", observations)
	}
}

func TestExecuteSYNFallsBackToIPv6ForIPv6OnlyHostname(t *testing.T) {
	transport := &dualSYNTransport{v4Err: httpengine.ErrSYNUnsupported}
	engine := Engine{SYN: transport}
	target := policy.Target{Hostname: "ipv6.example"}
	request := httpengine.SYNScanRequest{ProjectID: "test", Target: target, Ports: []uint16{443}, Timeout: time.Second}
	if _, err := engine.executeSYN(context.Background(), target, request); err != nil {
		t.Fatal(err)
	}
	if transport.v4Calls != 1 || transport.v6Calls != 1 {
		t.Fatalf("v4Calls=%d v6Calls=%d, want 1/1", transport.v4Calls, transport.v6Calls)
	}
}

type ipv4OnlySYNTransport struct{}

func (ipv4OnlySYNTransport) ScanSYN(context.Context, httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	return nil, nil
}

func TestExecuteSYNRejectsIPv6WhenAdapterIsIPv4Only(t *testing.T) {
	engine := Engine{SYN: ipv4OnlySYNTransport{}}
	target := policy.Target{IP: netip.MustParseAddr("2001:db8::10")}
	request := httpengine.SYNScanRequest{ProjectID: "test", Target: target, Ports: []uint16{443}, Timeout: time.Second}
	_, err := engine.executeSYN(context.Background(), target, request)
	if !errors.Is(err, httpengine.ErrSYN6Unsupported) {
		t.Fatalf("error=%v, want ErrSYN6Unsupported", err)
	}
}
