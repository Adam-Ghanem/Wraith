package httpengine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func TestValidateICMP6RequestSortsAndDeduplicates(t *testing.T) {
	targets, err := validateICMP6Request(ICMPScanRequest{
		ProjectID: "test",
		Targets: []netip.Addr{
			netip.MustParseAddr("2001:db8::2"),
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("2001:db8::2"),
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")}
	if len(targets) != len(want) {
		t.Fatalf("targets=%d, want %d", len(targets), len(want))
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("target[%d]=%s, want %s", i, targets[i], want[i])
		}
	}
}

func TestValidateICMP6RequestPreservesZones(t *testing.T) {
	target := netip.MustParseAddr("fe80::1%eth0")
	targets, err := validateICMP6Request(ICMPScanRequest{ProjectID: "test", Targets: []netip.Addr{target}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != target {
		t.Fatalf("targets=%v, want %s", targets, target)
	}
}

func TestValidateICMP6RequestRejectsIPv4(t *testing.T) {
	_, err := validateICMP6Request(ICMPScanRequest{ProjectID: "test", Targets: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Timeout: time.Second})
	if err == nil {
		t.Fatal("expected IPv4 target to be rejected")
	}
}

func TestParseICMP6EchoReply(t *testing.T) {
	message := icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 4242, Seq: 7, Data: []byte("WRAITH-ICMP6")},
	}
	payload, err := message.Marshal(icmp.IPv6PseudoHeader(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")))
	if err != nil {
		t.Fatal(err)
	}
	seq, address, ok := parseICMP6EchoReply(payload, &net.IPAddr{IP: net.ParseIP("2001:db8::1")}, 4242)
	if !ok {
		t.Fatal("expected echo reply to parse")
	}
	if seq != 7 || address != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("seq=%d address=%s", seq, address)
	}
}

func TestParseICMP6EchoReplyRejectsWrongIdentifier(t *testing.T) {
	message := icmp.Message{Type: ipv6.ICMPTypeEchoReply, Code: 0, Body: &icmp.Echo{ID: 1, Seq: 1}}
	payload, err := message.Marshal(icmp.IPv6PseudoHeader(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := parseICMP6EchoReply(payload, &net.IPAddr{IP: net.ParseIP("2001:db8::1")}, 2); ok {
		t.Fatal("wrong identifier unexpectedly accepted")
	}
}
