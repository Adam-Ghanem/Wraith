package portscan

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseXMLFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/nmap_sample.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings, err := ParseXML(data, Target{IP: "192.0.2.10", Subdomain: "app.example.com"})
	if err != nil {
		t.Fatalf("parse XML: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if findings[0].Port != 80 || findings[0].Protocol != "tcp" || findings[0].Service != "http" || findings[0].Source != "nmap" {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Banner, "nginx") {
		t.Fatalf("expected service evidence in banner: %+v", findings[0])
	}
	if findings[1].Port != 443 || findings[1].Status != "open|filtered" {
		t.Fatalf("unexpected second finding: %+v", findings[1])
	}
}

func TestParseXMLIgnoresOtherHostsAndClosedPorts(t *testing.T) {
	data := []byte(`<nmaprun><host><address addr="192.0.2.11"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host><host><address addr="192.0.2.10"/><ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>`)
	findings, err := ParseXML(data, Target{IP: "192.0.2.10"})
	if err != nil {
		t.Fatalf("parse XML: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got findings outside open target ports: %+v", findings)
	}
}

func TestParseXMLRejectsMalformedInput(t *testing.T) {
	if _, err := ParseXML([]byte(`<nmaprun>`), Target{IP: "192.0.2.10"}); err == nil {
		t.Fatal("expected malformed XML error")
	}
}

func TestBuildArgsUsesConservativeConnectProfile(t *testing.T) {
	args := BuildArgs(Target{IP: "192.0.2.10"}, 1000)
	joined := strings.Join(args, " ")
	for _, required := range []string{"-sT", "-n", "-Pn", "-T3", "--top-ports 1000", "--max-retries 2", "--open", "-oX -", "192.0.2.10"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("args %q missing %q", joined, required)
		}
	}
	if strings.Contains(joined, "-A") || strings.Contains(joined, "-sV") || strings.Contains(joined, "-O") || strings.Contains(joined, "--script") {
		t.Fatalf("args enable disallowed aggressive features: %q", joined)
	}
}

func TestScanSkipsWhenBinaryMissing(t *testing.T) {
	original := lookupBinary
	lookupBinary = func(string) (string, error) { return "", errors.New("not installed") }
	t.Cleanup(func() { lookupBinary = original })
	result, err := Scan(context.Background(), []Target{{IP: "192.0.2.10"}}, Config{Timeout: time.Second, TopPorts: 1000})
	if err != nil {
		t.Fatalf("missing optional binary should not fail scan: %v", err)
	}
	if !result.Skipped || len(result.Findings) != 0 {
		t.Fatalf("unexpected missing-binary result: %+v", result)
	}
}

func TestConfigRejectsUnboundedValues(t *testing.T) {
	if err := (Config{Timeout: 0, TopPorts: 1000}).Validate(); err == nil {
		t.Fatal("expected timeout validation error")
	}
	if err := (Config{Timeout: time.Minute, TopPorts: 0}).Validate(); err == nil {
		t.Fatal("expected top-port validation error")
	}
}
