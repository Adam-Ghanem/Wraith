package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/config"
	"github.com/Adam-Ghanem/Wraith/internal/ports"
)

type fakeDialer struct {
	mu          sync.Mutex
	calls       []string
	active      int
	maxActive   int
	openPort    uint16
	writeBanner string
}

func (d *fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, address)
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		d.mu.Unlock()
	}()

	portText := address[strings.LastIndex(address, ":")+1:]
	port, _ := strconv.ParseUint(portText, 10, 16)
	if uint16(port) != d.openPort {
		return nil, errors.New("connection refused")
	}

	client, server := net.Pipe()
	go func() {
		_, _ = server.Write([]byte(d.writeBanner))
		_ = server.Close()
	}()
	return client, nil
}

func authorizedScope() config.Scope {
	return config.Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("192.168.1.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/24"),
		Authorized:  true,
	}
}

func TestProbeTargetRejectsTargetOutsideSelectedCIDR(t *testing.T) {
	dialer := &fakeDialer{openPort: 80}
	_, err := ProbeTarget(context.Background(), authorizedScope(), netip.MustParseAddr("192.168.2.20"), ports.CuratedTop100TCP, Options{Concurrency: 4, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second}, dialer)
	if err == nil {
		t.Fatal("expected target outside selected CIDR to fail closed")
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("scope violation must send no connections, got %d", len(dialer.calls))
	}
}

func TestProbeTargetRequiresExactCuratedPortSet(t *testing.T) {
	dialer := &fakeDialer{openPort: 80}
	_, err := ProbeTarget(context.Background(), authorizedScope(), netip.MustParseAddr("192.168.1.20"), []uint16{80}, Options{Concurrency: 1, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second}, dialer)
	if err == nil {
		t.Fatal("expected non-curated port set to fail closed")
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("invalid port set must send no connections, got %d", len(dialer.calls))
	}
}

func TestProbeTargetUsesBoundedConcurrencyAndReadOnlyMetadata(t *testing.T) {
	dialer := &fakeDialer{openPort: 80, writeBanner: "HTTP/1.1 200 OK\r\nServer: lab\r\n"}
	results, err := ProbeTarget(context.Background(), authorizedScope(), netip.MustParseAddr("192.168.1.20"), ports.CuratedTop100TCP, Options{Concurrency: 3, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second}, dialer)
	if err != nil {
		t.Fatalf("probe target: %v", err)
	}
	if len(results) != len(ports.CuratedTop100TCP) {
		t.Fatalf("expected %d port results, got %d", len(ports.CuratedTop100TCP), len(results))
	}
	if dialer.maxActive > 3 {
		t.Fatalf("concurrency exceeded limit: %d", dialer.maxActive)
	}
	var foundOpen bool
	for _, result := range results {
		if result.Port == 80 {
			foundOpen = true
			if result.Status != "open" || result.Banner == "" {
				t.Fatalf("expected read-only metadata for open port: %+v", result)
			}
		}
	}
	if !foundOpen {
		t.Fatal("expected port 80 result")
	}
}

func TestOptionsRejectsUnboundedValues(t *testing.T) {
	cases := []Options{
		{Concurrency: 0, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second},
		{Concurrency: 2, ConnectTimeout: 0, MetadataMaxBytes: 128, MetadataTimeout: time.Second},
		{Concurrency: 2, ConnectTimeout: time.Second, MetadataMaxBytes: 0, MetadataTimeout: time.Second},
		{Concurrency: 2, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: 0},
	}
	for i, options := range cases {
		if err := options.Validate(); err == nil {
			t.Fatalf("case %d: expected invalid options to fail closed", i)
		}
	}
}

func TestAddressFormattingUsesIPv4Literal(t *testing.T) {
	address := netip.MustParseAddr("192.168.1.20")
	if got := formatAddress(address, 80); got != "192.168.1.20:80" {
		t.Fatalf("unexpected address: %s", got)
	}
	if !strings.Contains(fmt.Sprint(address), ".") {
		t.Fatal("test fixture is not IPv4")
	}
}

func TestProbeTargetUsesBannerSignatureForServiceGuess(t *testing.T) {
	dialer := &fakeDialer{openPort: 22, writeBanner: "HTTP/1.1 200 OK\r\nServer: lab\r\n"}
	results, err := ProbeTarget(context.Background(), authorizedScope(), netip.MustParseAddr("192.168.1.20"), ports.CuratedTop100TCP, Options{Concurrency: 2, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second}, dialer)
	if err != nil {
		t.Fatalf("probe target: %v", err)
	}
	for _, result := range results {
		if result.Port == 22 {
			if result.Service != "http" {
				t.Fatalf("expected banner signature to identify HTTP, got %q", result.Service)
			}
			return
		}
	}
	t.Fatal("expected port 22 result")
}

func TestOptionsAllowsConfiguredConcurrencyUpTo100(t *testing.T) {
	options := Options{Concurrency: 100, ConnectTimeout: time.Second, MetadataMaxBytes: 128, MetadataTimeout: time.Second}
	if err := options.Validate(); err != nil {
		t.Fatalf("expected concurrency 100 to be valid: %v", err)
	}
}
