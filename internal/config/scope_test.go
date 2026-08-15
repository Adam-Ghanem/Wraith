package config

import (
	"net/netip"
	"testing"
)

func TestValidateScopeAcceptsAuthorizedLocalIPv4Scope(t *testing.T) {
	scope := Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("192.168.1.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/24"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err != nil {
		t.Fatalf("expected valid scope, got %v", err)
	}
}

func TestValidateScopeRejectsMissingAuthorization(t *testing.T) {
	scope := Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("192.168.1.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/24"),
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected missing authorization to fail closed")
	}
}

func TestValidateScopeRejectsInterfaceAddressOutsideCIDR(t *testing.T) {
	scope := Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("192.168.2.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/24"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected interface/CIDR mismatch to fail closed")
	}
}

func TestValidateScopeRejectsLoopbackInterface(t *testing.T) {
	scope := Scope{
		Interface:   "lo",
		InterfaceIP: netip.MustParseAddr("127.0.0.1"),
		CIDR:        netip.MustParsePrefix("127.0.0.0/8"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected loopback scope to fail closed")
	}
}

func TestValidateScopeRejectsIPv6(t *testing.T) {
	scope := Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("2001:db8::10"),
		CIDR:        netip.MustParsePrefix("2001:db8::/64"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected IPv6 scope to fail closed in Phase 1")
	}
}

func TestValidateScopeRejectsMissingInterface(t *testing.T) {
	scope := Scope{
		InterfaceIP: netip.MustParseAddr("192.168.1.10"),
		CIDR:        netip.MustParsePrefix("192.168.1.0/24"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected missing interface to fail closed")
	}
}
