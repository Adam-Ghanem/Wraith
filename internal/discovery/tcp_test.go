package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeTCPProbe struct {
	mu   sync.Mutex
	live map[string]bool
	seen []string
}

func (p *fakeTCPProbe) ProbeTCP(_ context.Context, address netip.Addr, port uint16, _ time.Duration) error {
	key := fmt.Sprintf("%s:%d", address, port)
	p.mu.Lock()
	p.seen = append(p.seen, key)
	live := p.live[address.String()]
	p.mu.Unlock()
	if live {
		return nil
	}
	return errors.New("probe failed")
}

func (p *fakeTCPProbe) seenCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

func TestTCPDiscoveryDeduplicatesAndSortsLiveHosts(t *testing.T) {
	probe := &fakeTCPProbe{live: map[string]bool{
		"192.0.2.3": true,
		"192.0.2.1": true,
	}}
	targets := []netip.Addr{
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.2"),
	}

	got, err := DiscoverTCP(context.Background(), targets, TCPDiscoveryOptions{
		MaxTargets:  10,
		Concurrency: 2,
		Timeout:     time.Second,
		Ports:       []uint16{80, 443},
	}, probe)
	if err != nil {
		t.Fatalf("DiscoverTCP returned error: %v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.3"}
	if len(got) != len(want) {
		t.Fatalf("got %d hosts, want %d", len(got), len(want))
	}
	for i, address := range got {
		if address.String() != want[i] {
			t.Fatalf("got host %q at index %d, want %q", address, i, want[i])
		}
	}
}

func TestTCPDiscoveryStopsAfterFirstSuccessfulPort(t *testing.T) {
	probe := &fakeTCPProbe{live: map[string]bool{"192.0.2.10": true}}
	_, err := DiscoverTCP(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.10")}, TCPDiscoveryOptions{
		MaxTargets:  10,
		Concurrency: 1,
		Timeout:     time.Second,
		Ports:       []uint16{80, 443, 8080},
	}, probe)
	if err != nil {
		t.Fatalf("DiscoverTCP returned error: %v", err)
	}
	if got := probe.seenCount(); got != 1 {
		t.Fatalf("got %d probes, want 1", got)
	}
}

func TestTCPDiscoveryRejectsUnboundedOptions(t *testing.T) {
	cases := []TCPDiscoveryOptions{
		{MaxTargets: 0, Concurrency: 1, Timeout: time.Second, Ports: []uint16{80}},
		{MaxTargets: MaxTCPDiscoveryTargets + 1, Concurrency: 1, Timeout: time.Second, Ports: []uint16{80}},
		{MaxTargets: 1, Concurrency: 0, Timeout: time.Second, Ports: []uint16{80}},
		{MaxTargets: 1, Concurrency: 1, Timeout: time.Second, Ports: make([]uint16, MaxTCPDiscoveryPorts+1)},
	}
	for i, options := range cases {
		if err := options.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestTCPDiscoveryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := &fakeTCPProbe{}
	_, err := DiscoverTCP(ctx, []netip.Addr{netip.MustParseAddr("192.0.2.20")}, TCPDiscoveryOptions{
		MaxTargets:  1,
		Concurrency: 1,
		Timeout:     time.Second,
		Ports:       []uint16{80},
	}, probe)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}
