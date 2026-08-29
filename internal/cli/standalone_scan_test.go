package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scan"
)

func TestStandaloneTargetAcceptsIPHostnameAndTCP(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10":         "tcp://192.0.2.10/",
		"example.com":        "tcp://example.com/",
		"tcp://example.com/": "tcp://example.com/",
	}
	for input, want := range cases {
		got, err := standaloneTarget(input)
		if err != nil {
			t.Fatalf("standaloneTarget(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("standaloneTarget(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestStandaloneTargetsExpandsCIDR(t *testing.T) {
	targets, err := standaloneTargets("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tcp://192.0.2.0/",
		"tcp://192.0.2.1/",
		"tcp://192.0.2.2/",
		"tcp://192.0.2.3/",
	}
	if len(targets) != len(want) {
		t.Fatalf("targets=%d, want %d", len(targets), len(want))
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("target[%d]=%q, want %q", i, targets[i], want[i])
		}
	}
}

func TestStandaloneTargetsRejectsOversizedCIDR(t *testing.T) {
	if _, err := standaloneTargets("10.0.0.0/8"); err == nil {
		t.Fatalf("expected CIDR larger than %d targets to fail", scan.MaxTargets)
	}
}

func TestStandaloneTargetRejectsPortAndURLTargets(t *testing.T) {
	for _, input := range []string{"192.0.2.10:443", "https://example.com/", "", "12345"} {
		if _, err := standaloneTarget(input); err == nil {
			t.Fatalf("standaloneTarget(%q) unexpectedly accepted", input)
		}
	}
}

func TestStandaloneProfileAndPortPlanning(t *testing.T) {
	ports := npd.DefaultPorts(npd.ProfileDeep)
	if len(ports) != 1024 {
		t.Fatalf("deep profile has %d ports, want 1024", len(ports))
	}
	parsed, err := npd.ParsePorts("22,80,80,443,100-102", npd.MaxPorts)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Trim(strings.Join([]string{"22", "80", "100", "101", "102", "443"}, ","), " "); got != "22,80,100,101,102,443" {
		t.Fatalf("unexpected deterministic port expectation: %s", got)
	}
	if len(parsed) != 6 {
		t.Fatalf("parsed %v has %d ports, want 6", parsed, len(parsed))
	}
}

func TestStandaloneGatewayDoesNotRequireAuthorizationRecord(t *testing.T) {
	decision, err := (standaloneGateway{}).Authorize(context.Background(), "standalone", policy.Target{Scheme: string(policy.ProtocolTCP), Hostname: "example.com"}, policy.ActionConnect)
	if err != nil {
		t.Fatalf("standalone gateway authorization: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("standalone gateway unexpectedly denied the standalone scan")
	}
}

func TestRunStandaloneScanRequiresTarget(t *testing.T) {
	err := RunStandaloneScan(context.Background(), []string{"scan"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected usage error")
	}
}
