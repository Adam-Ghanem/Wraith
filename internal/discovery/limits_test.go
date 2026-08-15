package discovery

import (
	"net/netip"
	"testing"
)

func TestCandidateCountExcludesNetworkAndBroadcastForNormalIPv4CIDR(t *testing.T) {
	count, err := CandidateCount(netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil {
		t.Fatalf("candidate count: %v", err)
	}
	if count != 254 {
		t.Fatalf("expected 254 usable candidates, got %d", count)
	}
}

func TestCandidateCountRejectsNonIPv4CIDR(t *testing.T) {
	if _, err := CandidateCount(netip.MustParsePrefix("2001:db8::/64")); err == nil {
		t.Fatal("expected IPv6 candidate count to fail closed")
	}
}
