package contentdiscovery

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestDiscoverUsesProjectScopedHTTPTransport(t *testing.T) {
	client := &sequencedHTTPClient{responses: []httpengine.Response{
		{StatusCode: http.StatusNotFound, Body: []byte("baseline")},
		{StatusCode: http.StatusOK, Body: []byte("admin")},
	}}
	findings, err := Discover(context.Background(), "https://example.com/", Config{Concurrency: 1, PerHostPerSecond: 20, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5, Wordlist: []string{"/admin"}}, "project-a", client)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "/admin" {
		t.Fatalf("findings=%+v, want /admin", findings)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want baseline plus candidate", len(client.requests))
	}
	for _, request := range client.requests {
		if request.ProjectID != "project-a" || request.Method != http.MethodGet || request.MaxResponseBytes != 1024 || request.Headers.Get("User-Agent") != "Wraith/Phase3-authorized-content" {
			t.Fatalf("request=%#v, want project-scoped Phase 3 R3 request", request)
		}
	}
}

type sequencedHTTPClient struct {
	requests  []httpengine.Request
	responses []httpengine.Response
}

func (client *sequencedHTTPClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	response := client.responses[0]
	client.responses = client.responses[1:]
	return response, nil
}
