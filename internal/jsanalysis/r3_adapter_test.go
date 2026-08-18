package jsanalysis

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestAnalyzePageUsesProjectScopedHTTPTransport(t *testing.T) {
	client := &scriptHTTPClient{responses: []httpengine.Response{
		{StatusCode: http.StatusOK, Body: []byte(`<script src="/app.js"></script>`)},
		{StatusCode: http.StatusOK, Body: []byte(`const route = "/api/v1/status"`)},
	}}
	result, err := AnalyzePage(context.Background(), "example.com", "https://example.com/", Config{Concurrency: 1, PerHostPerSecond: 20, Timeout: time.Second, MaxFileBytes: 1024, MaxFindings: 10}, "project-a", client)
	if err != nil {
		t.Fatalf("AnalyzePage: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Value != "/api/v1/status" {
		t.Fatalf("result=%+v, want endpoint finding from R3-fetched script", result)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want page plus script", len(client.requests))
	}
	for _, request := range client.requests {
		if request.ProjectID != "project-a" || request.Method != http.MethodGet || request.MaxResponseBytes != 1024 || request.Headers.Get("User-Agent") != "Wraith/Phase3-authorized-js" {
			t.Fatalf("request=%#v, want project-scoped Phase 3 R3 request", request)
		}
	}
}

type scriptHTTPClient struct {
	requests  []httpengine.Request
	responses []httpengine.Response
}

func (client *scriptHTTPClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	response := client.responses[0]
	client.responses = client.responses[1:]
	return response, nil
}
