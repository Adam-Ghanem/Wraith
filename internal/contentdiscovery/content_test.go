package contentdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBaselineComparisonFiltersSoft404sAndKeepsMeaningfulFindings(t *testing.T) {
	baseline := Baseline{StatusCode: http.StatusOK, ResponseLength: 19, BodyHash: HashBody([]byte("soft not found page"))}
	cases := []struct {
		name       string
		response   Response
		meaningful bool
	}{
		{name: "same soft 404", response: Response{StatusCode: http.StatusOK, Body: []byte("soft not found page")}, meaningful: false},
		{name: "real 200", response: Response{StatusCode: http.StatusOK, Body: []byte("real admin content")}, meaningful: true},
		{name: "different forbidden", response: Response{StatusCode: http.StatusForbidden, Body: []byte("protected admin")}, meaningful: true},
		{name: "redirect", response: Response{StatusCode: http.StatusFound, Body: []byte("redirect")}, meaningful: true},
		{name: "other status", response: Response{StatusCode: http.StatusNotFound, Body: []byte("missing")}, meaningful: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := IsMeaningfulFinding(testCase.response, baseline); got != testCase.meaningful {
				t.Fatalf("meaningful=%v, want %v", got, testCase.meaningful)
			}
		})
	}
}

func TestDiscoverUsesBoundedConcurrencyAndPerHostRate(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		defer active.Add(-1)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()
	config := Config{Concurrency: 2, PerHostPerSecond: 20, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5, Wordlist: []string{"a", "b", "c", "d"}}
	findings, err := Discover(context.Background(), server.URL, config, server.Client())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected soft-404 findings to be filtered, got %+v", findings)
	}
	if maxActive.Load() > int32(config.Concurrency) {
		t.Fatalf("max concurrency=%d, limit=%d", maxActive.Load(), config.Concurrency)
	}
}

func TestConfigRejectsUnboundedContentDiscovery(t *testing.T) {
	for _, config := range []Config{
		{Concurrency: 51, PerHostPerSecond: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 1},
		{Concurrency: 1, PerHostPerSecond: 0, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 1},
		{Concurrency: 1, PerHostPerSecond: 1, Timeout: time.Second, MaxBodyBytes: 5 << 20, MaxRedirects: 1},
		{Concurrency: 1, PerHostPerSecond: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 6},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("expected config rejection for %+v", config)
		}
	}
}

func TestNormalizePathRejectsAbsoluteOrEscapingPaths(t *testing.T) {
	for _, path := range []string{"https://other.example/", "//other.example/", "../secret", ""} {
		if _, err := NormalizePath(path); err == nil || !strings.Contains(err.Error(), "path") {
			t.Fatalf("expected path rejection for %q, got %v", path, err)
		}
	}
	if normalized, err := NormalizePath("admin"); err != nil || normalized != "/admin" {
		t.Fatalf("normalize admin: %q %v", normalized, err)
	}
}
