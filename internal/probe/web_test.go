package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestProbeURLCapturesRedirectAndReadOnlyMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("Server", "phase2-lab")
			w.Header().Set("X-Powered-By", "Go")
			_, _ = io.WriteString(w, "<html><head><title>Lab Console</title></head><body>ok</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := ProbeURL(context.Background(), server.URL+"/redirect", WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 4096, MaxRedirects: 5}, "project-a", newProbeTestClient())
	if err != nil {
		t.Fatalf("probe URL: %v", err)
	}
	if result.StatusCode != http.StatusOK || result.Title != "Lab Console" || result.ServerHeader != "phase2-lab" || result.FinalURL != server.URL+"/final" {
		t.Fatalf("unexpected probe result: %+v", result)
	}
	if result.TechGuess != "go" {
		t.Fatalf("expected Go tech guess, got %q", result.TechGuess)
	}
}

func TestGuessTechnologyUsesHeadersAndMetaGenerator(t *testing.T) {
	if got := GuessTechnology(http.Header{"X-Powered-By": []string{"Express"}}, ""); got != "express" {
		t.Fatalf("expected express, got %q", got)
	}
	if got := GuessTechnology(http.Header{"Server": []string{"nginx/1.25"}}, "<meta name=\"generator\" content=\"WordPress\">"); got != "wordpress" {
		t.Fatalf("expected wordpress, got %q", got)
	}
}

func TestWebConfigRejectsUnboundedValues(t *testing.T) {
	cases := []WebConfig{
		{Concurrency: 0, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5},
		{Concurrency: 51, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5},
		{Concurrency: 1, Timeout: 0, MaxBodyBytes: 1024, MaxRedirects: 5},
		{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 0, MaxRedirects: 5},
		{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 6},
	}
	for i, config := range cases {
		if err := config.Validate(); err == nil {
			t.Fatalf("case %d: expected invalid web config to fail closed", i)
		}
	}
}

func TestProbeURLRejectsRedirectOutsideAuthorizedHostnameBoundary(t *testing.T) {
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://outside.example.invalid/", http.StatusFound)
	}))
	defer inside.Close()

	_, err := ProbeURL(context.Background(), inside.URL, WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5}, "project-a", newProbeTestClient())
	if err == nil || !strings.Contains(err.Error(), "authorized hostname") {
		t.Fatalf("expected authorized-host redirect error, got %v", err)
	}
}

func newProbeTestClient() httpengine.Client {
	return httpengine.NewEngine(httpengine.Config{Gateway: probeAllowGateway{}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}})
}

type probeAllowGateway struct{}

func (probeAllowGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action}, nil
}
