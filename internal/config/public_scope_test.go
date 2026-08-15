package config

import (
	"net/netip"
	"testing"
)

func TestValidateScopeRejectsGloballyRoutableCIDR(t *testing.T) {
	scope := Scope{
		Interface:   "eth0",
		InterfaceIP: netip.MustParseAddr("8.8.8.10"),
		CIDR:        netip.MustParsePrefix("8.8.8.0/24"),
		Authorized:  true,
	}

	if err := ValidateScope(scope); err == nil {
		t.Fatal("expected globally routable CIDR to fail closed")
	}
}
