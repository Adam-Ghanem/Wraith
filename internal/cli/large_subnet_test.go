package cli

import (
	"strings"
	"testing"
)

func TestParseOptionsAcceptsJSONAndSubnetAliases(t *testing.T) {
	options, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--subnet", "192.168.1.0/24",
		"--authorized",
		"--json",
	})
	if err != nil {
		t.Fatalf("parse aliases: %v", err)
	}
	if options.Format != "json" || options.CIDR.String() != "192.168.1.0/24" {
		t.Fatalf("unexpected alias result: %+v", options)
	}
}

func TestParseOptionsRequiresConfirmationForLargeSubnet(t *testing.T) {
	_, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--subnet", "192.168.0.0/23",
		"--authorized",
		"--arp-max-targets", "512",
	})
	if err == nil || !strings.Contains(err.Error(), "confirm-large-subnet") {
		t.Fatalf("expected large-subnet confirmation error, got %v", err)
	}

	options, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--subnet", "192.168.0.0/23",
		"--authorized",
		"--arp-max-targets", "512",
		"--confirm-large-subnet",
	})
	if err != nil {
		t.Fatalf("parse confirmed large subnet: %v", err)
	}
	if !options.ConfirmLargeSubnet {
		t.Fatal("expected large-subnet confirmation to be recorded")
	}
	if options.CandidateCount != 510 {
		t.Fatalf("expected 510 candidate hosts, got %d", options.CandidateCount)
	}
}

func TestParseOptionsRejectsCandidateCountAboveConfiguredARPLimit(t *testing.T) {
	_, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--subnet", "192.168.0.0/23",
		"--authorized",
		"--confirm-large-subnet",
		"--arp-max-targets", "256",
	})
	if err == nil || !strings.Contains(err.Error(), "ARP target limit") {
		t.Fatalf("expected configured ARP limit error, got %v", err)
	}
}
