package cli

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

type fakeICMP6Client struct {
	responses []httpengine.ICMPResponse
	err       error
	calls     int
}

func (f *fakeICMP6Client) DiscoverICMP6(_ context.Context, _ httpengine.ICMPScanRequest) ([]httpengine.ICMPResponse, error) {
	f.calls++
	return append([]httpengine.ICMPResponse(nil), f.responses...), f.err
}

type fakeDualSYNClient struct {
	v4Calls int
	v6Calls int
	v4Err   error
	v6Err   error
}

func (f *fakeDualSYNClient) ScanSYN(_ context.Context, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	f.v4Calls++
	return []httpengine.SYNResponse{{Port: request.Ports[0], State: httpengine.SYNStateClosed, TTL: 64}}, f.v4Err
}

func (f *fakeDualSYNClient) ScanSYN6(_ context.Context, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	f.v6Calls++
	return []httpengine.SYNResponse{{Port: request.Ports[0], State: httpengine.SYNStateClosed, TTL: 64}}, f.v6Err
}

func TestDiscoverStandaloneICMP6MarksLiveTargets(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::10")
	client := &fakeICMP6Client{responses: []httpengine.ICMPResponse{{IP: address}}}
	live := map[string]struct{}{}
	if err := discoverStandaloneICMP6(context.Background(), client, []netip.Addr{address}, live, time.Second); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("calls=%d, want 1", client.calls)
	}
	if _, ok := live["tcp://[2001:db8::10]/"]; !ok {
		t.Fatal("expected IPv6 target to be marked live")
	}
}

func TestDiscoverStandaloneICMP6FallsBackOnPermission(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::10")
	client := &fakeICMP6Client{err: httpengine.ErrICMPPermission}
	if err := discoverStandaloneICMP6(context.Background(), client, []netip.Addr{address}, map[string]struct{}{}, time.Second); err != nil {
		t.Fatalf("permission error should permit TCP fallback: %v", err)
	}
}

func TestScanStandaloneOSProbeRoutesExplicitIPv6(t *testing.T) {
	client := &fakeDualSYNClient{}
	_, err := scanStandaloneOSProbe(context.Background(), client, policy.Target{IP: netip.MustParseAddr("2001:db8::20")}, 443, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if client.v4Calls != 0 || client.v6Calls != 1 {
		t.Fatalf("v4=%d v6=%d, want 0/1", client.v4Calls, client.v6Calls)
	}
}

func TestScanStandaloneOSProbeFallsBackFromHostnameToIPv6(t *testing.T) {
	client := &fakeDualSYNClient{v4Err: httpengine.ErrSYNUnsupported}
	_, err := scanStandaloneOSProbe(context.Background(), client, policy.Target{Hostname: "ipv6-only.example"}, 443, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if client.v4Calls != 1 || client.v6Calls != 1 {
		t.Fatalf("v4=%d v6=%d, want 1/1", client.v4Calls, client.v6Calls)
	}
}

func TestDiscoverStandaloneICMP6ReturnsPolicyErrors(t *testing.T) {
	client := &fakeICMP6Client{err: httpengine.ErrTCPPolicyDenied}
	err := discoverStandaloneICMP6(context.Background(), client, []netip.Addr{netip.MustParseAddr("2001:db8::10")}, map[string]struct{}{}, time.Second)
	if !errors.Is(err, httpengine.ErrTCPPolicyDenied) {
		t.Fatalf("err=%v, want policy denial", err)
	}
}
