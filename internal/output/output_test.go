package output

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/model"
)

func sampleResult() model.Result {
	return model.Result{
		SchemaVersion: "phase1.v1",
		Scope: model.Scope{
			Interface:              "eth0",
			CIDR:                   "192.168.1.0/24",
			AuthorizationConfirmed: true,
		},
		PortList: model.PortList{Name: "curated-top100-tcp", Version: "2026-08-curated-v1"},
		Run:      model.Run{Status: "complete"},
		Targets: []model.Target{{
			IP:        netip.MustParseAddr("192.168.1.20"),
			MAC:       "02:00:00:00:00:20",
			Discovery: "arp-response",
			Ports:     []model.PortResult{{Port: 80, Status: "open", Service: "http"}},
		}},
	}
}

func TestRenderJSONIncludesScopeAndTargets(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleResult()); err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	text := buf.String()
	for _, want := range []string{"\"schema_version\": \"phase1.v1\"", "\"cidr\": \"192.168.1.0/24\"", "\"port\": 80"} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON output missing %q: %s", want, text)
		}
	}
}

func TestRenderTerminalShowsBoundaryBeforeObservations(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderTerminal(&buf, sampleResult()); err != nil {
		t.Fatalf("render terminal: %v", err)
	}
	text := buf.String()
	for _, want := range []string{"Interface: eth0", "CIDR: 192.168.1.0/24", "Authorization: confirmed", "192.168.1.20", "80", "open"} {
		if !strings.Contains(text, want) {
			t.Fatalf("terminal output missing %q: %s", want, text)
		}
	}
	if strings.Index(text, "CIDR: 192.168.1.0/24") > strings.Index(text, "192.168.1.20") {
		t.Fatal("terminal output must show the selected boundary before observations")
	}
}
