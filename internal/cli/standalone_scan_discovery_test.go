package cli

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type fakeStandaloneDiscoveryTCP struct{}

func (fakeStandaloneDiscoveryTCP) ProbeTCP(_ context.Context, request httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	if request.Target.Hostname == "up.example" && request.Target.Port == 80 {
		return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPRefused
	}
	return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPTimeout
}

type fakeLayeredDiscovery struct {
	tcpCalls int
}

func (f *fakeLayeredDiscovery) ProbeTCP(_ context.Context, _ httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.tcpCalls++
	return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPRefused
}

func (f *fakeLayeredDiscovery) DiscoverICMP(_ context.Context, request httpengine.ICMPScanRequest) ([]httpengine.ICMPResponse, error) {
	if len(request.Targets) == 0 {
		return nil, nil
	}
	return []httpengine.ICMPResponse{{IP: request.Targets[0], Duration: time.Millisecond}}, nil
}

type fakeIPv6LayeredDiscovery struct {
	tcpCalls int
}

func (f *fakeIPv6LayeredDiscovery) ProbeTCP(_ context.Context, _ httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.tcpCalls++
	return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPRefused
}

func (f *fakeIPv6LayeredDiscovery) DiscoverICMP6(_ context.Context, request httpengine.ICMPScanRequest) ([]httpengine.ICMPResponse, error) {
	if len(request.Targets) == 0 {
		return nil, nil
	}
	return []httpengine.ICMPResponse{{IP: request.Targets[0], Duration: time.Millisecond}}, nil
}

func TestDiscoverStandaloneTargetsActivelyChecksHostnames(t *testing.T) {
	targets, err := discoverStandaloneTargets(
		context.Background(),
		fakeStandaloneDiscoveryTCP{},
		[]string{"tcp://up.example/", "tcp://down.example/"},
		50*time.Millisecond,
		2,
	)
	if err != nil {
		t.Fatalf("discoverStandaloneTargets() error = %v", err)
	}
	if len(targets) != 1 || targets[0] != "tcp://up.example/" {
		t.Fatalf("targets = %v, want [tcp://up.example/]", targets)
	}
}

func TestDiscoverStandaloneTargetsUsesICMPBeforeTCPFallback(t *testing.T) {
	transport := &fakeLayeredDiscovery{}
	targets, err := discoverStandaloneTargets(
		context.Background(),
		transport,
		[]string{"tcp://192.0.2.1/", "tcp://192.0.2.2/"},
		50*time.Millisecond,
		2,
	)
	if err != nil {
		t.Fatalf("discoverStandaloneTargets() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets=%v, want both hosts live", targets)
	}
	if transport.tcpCalls != 1 {
		t.Fatalf("TCP probes=%d, want 1 fallback probe after ICMP identified one live host", transport.tcpCalls)
	}
}

func TestDiscoverStandaloneTargetsUsesICMP6BeforeTCPFallback(t *testing.T) {
	transport := &fakeIPv6LayeredDiscovery{}
	targets, err := discoverStandaloneTargets(
		context.Background(),
		transport,
		[]string{"tcp://[2001:db8::1]/"},
		50*time.Millisecond,
		2,
	)
	if err != nil {
		t.Fatalf("discoverStandaloneTargets() error = %v", err)
	}
	if len(targets) != 1 || targets[0] != "tcp://[2001:db8::1]/" {
		t.Fatalf("targets=%v, want IPv6 host live", targets)
	}
	if transport.tcpCalls != 0 {
		t.Fatalf("TCP probes=%d, want 0 after ICMPv6 identified host live", transport.tcpCalls)
	}
}

func TestCommonIPv4PrefixMatchesExpandedCIDR(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("192.168.10.0"),
		netip.MustParseAddr("192.168.10.1"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("192.168.10.255"),
	}
	prefix, ok := commonIPv4Prefix(addresses)
	if !ok {
		t.Fatal("expected IPv4 prefix")
	}
	if want := netip.MustParsePrefix("192.168.10.0/24"); prefix != want {
		t.Fatalf("prefix=%s, want %s", prefix, want)
	}
}
