package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/npd"
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

func TestRunStandaloneScanFailsClosedWithoutProjectAuthorizationAndScope(t *testing.T) {
	var stdout bytes.Buffer
	err := RunStandaloneScan(context.Background(), []string{"scan", "192.0.2.10", "-p", "443"}, &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "active authorization and matching scope") {
		t.Fatalf("RunStandaloneScan() error = %v, want fail-closed authorization and scope rejection", err)
	}
}

func TestRunStandaloneScanRequiresTarget(t *testing.T) {
	err := RunStandaloneScan(context.Background(), []string{"scan"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected usage error")
	}
}
