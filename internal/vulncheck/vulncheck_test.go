package vulncheck

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseJSONLFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/nuclei_sample.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings, err := ParseJSONL(data)
	if err != nil {
		t.Fatalf("parse JSONL: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if findings[0].TemplateID != "exposed-panel" || findings[0].Severity != "medium" || findings[0].MatchedURL != "https://app.example.com/admin" {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
	if findings[1].TemplateID != "old-cve" || findings[1].Severity != "high" || findings[1].Description == "" {
		t.Fatalf("unexpected second finding: %+v", findings[1])
	}
}

func TestParseJSONLRejectsMalformedLine(t *testing.T) {
	if _, err := ParseJSONL([]byte(`{"template-id":"ok"}
not-json
`)); err == nil {
		t.Fatal("expected malformed JSONL error")
	}
}

func TestBuildArgsUsesConservativeTemplateAndRateFilters(t *testing.T) {
	args := BuildArgs(5)
	joined := strings.Join(args, " ")
	for _, required := range []string{"-tags", "cves,exposures,misconfiguration", "-exclude-tags", "fuzz,dast,headless,code,workflow,interactsh,dos,ddos,brute-force,default-login", "-rate-limit", "5", "-jsonl", "-no-color", "-silent", "-omit-raw", "-restrict-local-network-access", "-dr", "-ni", "-duc"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("args %q missing %q", joined, required)
		}
	}
	for _, disallowed := range []string{"-fuzz", "-dast", "-code", "-headless", "-interactsh", "-ai", "-allow-local-file-access", "-enable-self-contained"} {
		for _, arg := range args {
			if arg == disallowed {
				t.Fatalf("args enable disallowed intrusive feature %q: %s", disallowed, joined)
			}
		}
	}
}

func TestScanSkipsWhenBinaryMissing(t *testing.T) {
	original := lookupBinary
	lookupBinary = func(string) (string, error) { return "", errors.New("not installed") }
	t.Cleanup(func() { lookupBinary = original })
	result, err := Scan(context.Background(), []string{"https://app.example.com"}, Config{Timeout: time.Second, RateLimit: 5})
	if err != nil {
		t.Fatalf("missing optional binary should not fail scan: %v", err)
	}
	if !result.Skipped || len(result.Findings) != 0 {
		t.Fatalf("unexpected missing-binary result: %+v", result)
	}
}

func TestConfigRejectsUnboundedValues(t *testing.T) {
	if err := (Config{Timeout: 0, RateLimit: 5}).Validate(); err == nil {
		t.Fatal("expected timeout validation error")
	}
	if err := (Config{Timeout: 10 * time.Minute, RateLimit: 0}).Validate(); err == nil {
		t.Fatal("expected rate-limit validation error")
	}
}

func TestValidateTargetsEnforcesSameScanHTTPBounds(t *testing.T) {
	validated, hosts, err := validateTargets([]string{"https://app.example.com/", "https://app.example.com/"}, 2)
	if err != nil {
		t.Fatalf("validate targets: %v", err)
	}
	if len(validated) != 1 || hosts["app.example.com"] != "app.example.com" {
		t.Fatalf("unexpected validated targets=%v hosts=%v", validated, hosts)
	}
	if _, _, err := validateTargets([]string{"ftp://app.example.com/"}, 2); err == nil {
		t.Fatal("expected non-HTTP target rejection")
	}
	if _, _, err := validateTargets([]string{"https://a.example.com/", "https://b.example.com/"}, 1); err == nil {
		t.Fatal("expected target cap rejection")
	}
}
