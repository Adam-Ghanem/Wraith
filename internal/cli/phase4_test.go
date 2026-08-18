package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestParseScanOptionsAcceptsPhase4Flags(t *testing.T) {
	options, err := parseScanOptions([]string{"scan", "-d", "example.com", "--project", "project-a", "--authorized", "--use-nmap", "--use-nuclei"})
	if err != nil {
		t.Fatalf("parse Phase 4 flags: %v", err)
	}
	if !options.UseNmap || !options.UseNuclei || !options.Authorized {
		t.Fatalf("unexpected Phase 4 options: %+v", options)
	}
	if _, err := parseScanOptions([]string{"scan", "-d", "example.com", "--use-nmap"}); err == nil {
		t.Fatal("expected --use-nmap to retain authorization gate")
	}
}

func TestPhase4TargetsComeOnlyFromSameScanResults(t *testing.T) {
	nmap := nmapTargets([]enum.EnumResult{{Subdomain: "app.example.com", IP: "192.0.2.10"}, {Subdomain: "other.example.com", IP: "192.0.2.10"}, {Subdomain: "missing.example.com"}})
	if len(nmap) != 1 || nmap[0].IP != "192.0.2.10" {
		t.Fatalf("unexpected Nmap targets: %+v", nmap)
	}
	nuclei := nucleiTargets([]probe.WebResult{{Subdomain: "app.example.com", Scheme: "https", Alive: true, FinalURL: "https://app.example.com/"}, {Subdomain: "dead.example.com", Scheme: "https", Alive: false, FinalURL: "https://dead.example.com/"}})
	if len(nuclei) != 1 || nuclei[0] != "https://app.example.com/" {
		t.Fatalf("unexpected Nuclei targets: %+v", nuclei)
	}
}

func TestPhase4ScanJSONIncludesFindingSections(t *testing.T) {
	var output bytes.Buffer
	err := renderScanOutput(&output, true, scanOutput{
		ScanID:       1,
		Target:       "example.com",
		PortFindings: []storage.PortFindingRecord{{ID: 2, ScanID: 1, SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Service: "https", Source: "nmap"}},
		VulnFindings: []storage.VulnFindingRecord{{ID: 3, ScanID: 1, Subdomain: "app.example.com", TemplateID: "fixture-exposure", Severity: "medium", MatchedURL: "https://app.example.com/admin"}},
	})
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if _, ok := decoded["port_findings"]; !ok {
		t.Fatalf("missing port findings: %s", output.String())
	}
	if _, ok := decoded["vuln_findings"]; !ok {
		t.Fatalf("missing vulnerability findings: %s", output.String())
	}
}

func TestPhase4HistoryTerminalIncludesFindingSections(t *testing.T) {
	var output bytes.Buffer
	err := renderHistoryOutput(&output, false, historyOutput{
		PortChanges: []storage.PortFindingChange{{Kind: storage.ChangeNew, Current: storage.PortFindingSnapshot{SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Service: "https", Source: "nmap"}}},
		VulnChanges: []storage.VulnFindingChange{{Kind: storage.ChangeNew, Current: storage.VulnFindingSnapshot{Subdomain: "app.example.com", TemplateID: "fixture-exposure", Severity: "medium", MatchedURL: "https://app.example.com/admin"}}},
	})
	if err != nil {
		t.Fatalf("render history: %v", err)
	}
	for _, expected := range []string{"NEW PORT FINDINGS", "NEW VULNERABILITY FINDINGS", "fixture-exposure", "app.example.com"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("history missing %q: %s", expected, output.String())
		}
	}
}
