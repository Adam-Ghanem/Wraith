package httpengine

import (
	"net/netip"
	"testing"
	"time"
)

func TestValidateICMPRequestDeduplicatesAndSorts(t *testing.T) {
	targets, err := validateICMPRequest(ICMPScanRequest{
		ProjectID: "test",
		Targets: []netip.Addr{
			netip.MustParseAddr("192.0.2.3"),
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("192.0.2.3"),
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.3"}
	if len(targets) != len(want) {
		t.Fatalf("targets=%d, want %d", len(targets), len(want))
	}
	for i := range want {
		if targets[i].String() != want[i] {
			t.Fatalf("target[%d]=%s, want %s", i, targets[i], want[i])
		}
	}
}

func TestValidateICMPRequestRejectsIPv6(t *testing.T) {
	_, err := validateICMPRequest(ICMPScanRequest{
		ProjectID: "test",
		Targets:   []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		Timeout:   time.Second,
	})
	if err != ErrICMPUnsupported {
		t.Fatalf("error=%v, want %v", err, ErrICMPUnsupported)
	}
}

func TestValidateICMPRequestRejectsUnboundedBatch(t *testing.T) {
	targets := make([]netip.Addr, MaxICMPTargets+1)
	for i := range targets {
		targets[i] = netip.MustParseAddr("192.0.2.1")
	}
	_, err := validateICMPRequest(ICMPScanRequest{ProjectID: "test", Targets: targets, Timeout: time.Second})
	if err != ErrInvalidICMPRequest {
		t.Fatalf("error=%v, want %v", err, ErrInvalidICMPRequest)
	}
}
