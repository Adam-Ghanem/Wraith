package model

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestResultJSONRoundTripsPhase1Metadata(t *testing.T) {
	result := Result{
		SchemaVersion: "phase1.v1",
		Scope: Scope{
			Interface:              "eth0",
			CIDR:                   "192.168.1.0/24",
			AuthorizationConfirmed: true,
		},
		PortList: PortList{Name: "curated-top100-tcp", Version: "2026-08-curated-v1"},
		Run:      Run{Status: "complete"},
		Targets: []Target{{
			IP:        netip.MustParseAddr("192.168.1.20"),
			MAC:       "02:00:00:00:00:20",
			Discovery: "arp-response",
			Ports:     []PortResult{{Port: 80, Status: "open", Service: "http", Banner: "Server: lab"}},
		}},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if decoded.SchemaVersion != "phase1.v1" || decoded.Scope.CIDR != "192.168.1.0/24" {
		t.Fatalf("result lost scope metadata after round trip: %+v", decoded)
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].Ports[0].Port != 80 {
		t.Fatalf("result lost target metadata after round trip: %+v", decoded.Targets)
	}
}

func TestResultJSONDoesNotContainControlCharactersFromBanner(t *testing.T) {
	result := Result{
		SchemaVersion: "phase1.v1",
		Targets: []Target{{
			IP:    netip.MustParseAddr("192.168.1.20"),
			Ports: []PortResult{{Port: 22, Status: "open", Banner: "ssh\n\x1b[31mred"}},
		}},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(encoded), "\x1b") {
		t.Fatal("JSON must escape control characters in untrusted metadata")
	}
}
