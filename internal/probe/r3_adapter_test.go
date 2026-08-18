package probe

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestProbeURLUsesProjectScopedHTTPTransport(t *testing.T) {
	client := &recordingHTTPClient{response: httpengine.Response{
		StatusCode:    http.StatusOK,
		Headers:       http.Header{"Server": []string{"phase2-lab"}},
		ContentLength: 2,
		Body:          []byte("ok"),
		URL:           "https://example.com/",
	}}
	result, err := ProbeURL(context.Background(), "https://example.com/", WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5}, "project-a", client)
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if result.StatusCode != http.StatusOK || result.ServerHeader != "phase2-lab" {
		t.Fatalf("result=%+v, want metadata from R3 response", result)
	}
	request := client.requests[0]
	if request.ProjectID != "project-a" || request.Method != http.MethodGet || request.MaxResponseBytes != 1024 || request.Headers.Get("User-Agent") != "Wraith/Phase2-authorized-recon" {
		t.Fatalf("request=%#v, want project-scoped Phase 2 R3 request", request)
	}
}

type recordingHTTPClient struct {
	requests []httpengine.Request
	response httpengine.Response
	err      error
}

func (client *recordingHTTPClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	return client.response, client.err
}
