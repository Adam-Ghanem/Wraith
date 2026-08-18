package jsanalysis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestExtractScriptURLsResolvesRelativeReferences(t *testing.T) {
	html := []byte(`<html><script src="/static/app.js"></script><script src="chunk.js"></script><script>inline()</script></html>`)
	urls, err := ExtractScriptURLs("https://app.example.test/account/", html)
	if err != nil {
		t.Fatalf("extract script URLs: %v", err)
	}
	want := []string{"https://app.example.test/account/chunk.js", "https://app.example.test/static/app.js"}
	if len(urls) != len(want) {
		t.Fatalf("urls=%v, want %v", urls, want)
	}
	for index := range want {
		if urls[index] != want[index] {
			t.Fatalf("urls=%v, want %v", urls, want)
		}
	}
}

func TestExtractFindingsRedactsSecretsAndRejectsWeakMatches(t *testing.T) {
	body := []byte(`fetch('/api/v1/users'); const good = "AKIA1234567890ABCDEF"; const api_key = "abcdefghijklmnop"; const short = "api_key=short"; const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";`)
	findings := ExtractFindings("https://app.example.test/app.js", body)
	if !containsFinding(findings, FindingTypeEndpoint, "/api/v1/users", "observed") {
		t.Fatalf("expected endpoint finding, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.FindingType == FindingTypeSecret {
			if finding.Confidence != "potential" {
				t.Fatalf("secret confidence=%q, want potential", finding.Confidence)
			}
			if strings.Contains(finding.Value, "abcdefghijklmnop") || strings.Contains(finding.Value, "AKIA1234567890ABCDEF") {
				t.Fatalf("secret was not redacted: %+v", finding)
			}
		}
	}
	if len(findings) != 4 {
		t.Fatalf("findings=%+v, want endpoint plus three potential secrets", findings)
	}
	if got := RedactSecret("abcdefghijklmnop"); got != "abcd…mnop" {
		t.Fatalf("redaction=%q", got)
	}
}

func TestAnalyzeHTMLDeduplicatesScriptsAndCapsFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/js/app.js"></script><script src="js/app.js"></script>`))
		case "/js/app.js":
			_, _ = w.Write([]byte(`fetch('/api/users'); const api_key = "abcdefghijklmnop";`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config := Config{Concurrency: 2, PerHostPerSecond: 20, Timeout: time.Second, MaxFileBytes: 5 << 20, MaxFindings: 50}
	result, err := AnalyzeHTML(context.Background(), "app.example.test", server.URL+"/", []byte(`<script src="/js/app.js"></script><script src="js/app.js"></script>`), config, "project-a", newJSTestClient())
	if err != nil {
		t.Fatalf("analyze HTML: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("deduplicated findings=%+v, want two findings", result.Findings)
	}
	if len(result.ScriptFiles) != 1 {
		t.Fatalf("script files=%v, want one deduplicated file", result.ScriptFiles)
	}
}

func TestConfigRejectsUnboundedJSAnalysis(t *testing.T) {
	for _, config := range []Config{
		{Concurrency: 51, PerHostPerSecond: 1, Timeout: time.Second, MaxFileBytes: 1024, MaxFindings: 50},
		{Concurrency: 1, PerHostPerSecond: 0, Timeout: time.Second, MaxFileBytes: 1024, MaxFindings: 50},
		{Concurrency: 1, PerHostPerSecond: 1, Timeout: time.Second, MaxFileBytes: 6 << 20, MaxFindings: 50},
		{Concurrency: 1, PerHostPerSecond: 1, Timeout: time.Second, MaxFileBytes: 1024, MaxFindings: 51},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("expected config rejection for %+v", config)
		}
	}
}

func containsFinding(findings []Finding, kind FindingType, value, confidence string) bool {
	for _, finding := range findings {
		if finding.FindingType == kind && finding.Value == value && finding.Confidence == confidence {
			return true
		}
	}
	return false
}

func newJSTestClient() httpengine.Client {
	return httpengine.NewEngine(httpengine.Config{Gateway: jsAllowGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}})
}

type jsAllowGateway struct{}

func (jsAllowGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action}, nil
}
