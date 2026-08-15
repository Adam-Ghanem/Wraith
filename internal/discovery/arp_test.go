package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/config"
)

type fakeResolver struct {
	mu      sync.Mutex
	calls   []netip.Addr
	respond map[netip.Addr]net.HardwareAddr
}

func (r *fakeResolver) Resolve(_ context.Context, address netip.Addr) (net.HardwareAddr, error) {
	r.mu.Lock()
	r.calls = append(r.calls, address)
	mac, ok := r.respond[address]
	r.mu.Unlock()
	if !ok {
		return nil, errors.New("no ARP response")
	}
	return mac, nil
}

func TestEnumerateIPv4TargetsExcludesNetworkAndBroadcast(t *testing.T) {
	targets, err := EnumerateIPv4Targets(netip.MustParsePrefix("192.168.1.0/30"), 10)
	if err != nil {
		t.Fatalf("enumerate targets: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.2")}
	if len(targets) != len(want) {
		t.Fatalf("expected %d targets, got %d", len(want), len(targets))
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("target %d: want %s, got %s", i, want[i], targets[i])
		}
	}
}

func TestEnumerateIPv4TargetsFailsClosedWhenCIDRExceedsBound(t *testing.T) {
	if _, err := EnumerateIPv4Targets(netip.MustParsePrefix("192.168.0.0/16"), 10); err == nil {
		t.Fatal("expected oversized CIDR to fail closed")
	}
}

func TestDiscoverARPReturnsOnlyRespondingAuthorizedTargets(t *testing.T) {
	scope := config.Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("192.168.1.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/28"),
		Authorized:  true,
	}
	live := netip.MustParseAddr("192.168.1.2")
	resolver := &fakeResolver{respond: map[netip.Addr]net.HardwareAddr{
		live: {0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
	}}

	targets, err := DiscoverARP(context.Background(), scope, ARPOptions{MaxTargets: 20, Concurrency: 2, Timeout: time.Second}, resolver)
	if err != nil {
		t.Fatalf("discover ARP: %v", err)
	}
	if len(targets) != 1 || targets[0].IP != live || targets[0].MAC != "02:00:00:00:00:02" {
		t.Fatalf("unexpected live targets: %+v", targets)
	}
}

func TestARPOptionsRejectsUnboundedValues(t *testing.T) {
	cases := []ARPOptions{
		{MaxTargets: 0, Concurrency: 1, Timeout: time.Second},
		{MaxTargets: 10, Concurrency: 0, Timeout: time.Second},
		{MaxTargets: 10, Concurrency: 1, Timeout: 0},
		{MaxTargets: 5000, Concurrency: 1, Timeout: time.Second},
	}
	for i, options := range cases {
		if err := options.Validate(); err == nil {
			t.Fatalf("case %d: expected options to fail closed", i)
		}
	}
}
