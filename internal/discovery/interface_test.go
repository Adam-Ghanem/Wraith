package discovery

import (
	"net"
	"net/netip"
	"testing"
)

func TestSelectInterfaceIPv4RequiresExplicitCIDRMatch(t *testing.T) {
	iface := net.Interface{Name: "eth0", Flags: net.FlagUp}
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)},
	}

	selected, err := SelectInterfaceIPv4(iface, addrs, netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil {
		t.Fatalf("select interface IPv4: %v", err)
	}
	if selected != netip.MustParseAddr("192.168.1.10") {
		t.Fatalf("unexpected selected address: %s", selected)
	}
}

func TestSelectInterfaceIPv4RejectsDownOrLoopbackInterface(t *testing.T) {
	iface := net.Interface{Name: "lo", Flags: net.FlagLoopback}
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
	}

	if _, err := SelectInterfaceIPv4(iface, addrs, netip.MustParsePrefix("127.0.0.0/8")); err == nil {
		t.Fatal("expected loopback interface to be rejected")
	}
}

func TestSelectInterfaceIPv4RejectsAmbiguousMatch(t *testing.T) {
	iface := net.Interface{Name: "eth0", Flags: net.FlagUp}
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.11"), Mask: net.CIDRMask(24, 32)},
	}

	if _, err := SelectInterfaceIPv4(iface, addrs, netip.MustParsePrefix("192.168.1.0/24")); err == nil {
		t.Fatal("expected multiple matching IPv4 addresses to fail closed")
	}
}

func TestPrefixCoversRequestedOnlyForDirectSubnets(t *testing.T) {
	connected := netip.MustParsePrefix("192.168.1.0/24")
	if !prefixCoversRequested(connected, netip.MustParsePrefix("192.168.1.128/25")) {
		t.Fatal("expected directly connected /25 to be covered by /24")
	}
	if !prefixCoversRequested(connected, netip.MustParsePrefix("192.168.1.50/32")) {
		t.Fatal("expected host /32 to be covered by /24")
	}
	if prefixCoversRequested(connected, netip.MustParsePrefix("192.168.0.0/16")) {
		t.Fatal("wider routed prefix must not be treated as directly connected")
	}
	if prefixCoversRequested(connected, netip.MustParsePrefix("192.168.2.0/24")) {
		t.Fatal("different subnet must not be treated as directly connected")
	}
}
