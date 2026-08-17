package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

	result, err := ProbeURL(context.Background(), server.URL+"/redirect", WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 4096, MaxRedirects: 5}, server.Client())
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

func TestProbeURLRetriesTimeoutOnceOnly(t *testing.T) {
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, timeoutError{}
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}},
		}, nil
	})
	client := &http.Client{Transport: transport}
	result, err := ProbeURL(context.Background(), "https://example.com", WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5}, client)
	if err != nil {
		t.Fatalf("probe URL after timeout retry: %v", err)
	}
	if calls.Load() != 2 || result.StatusCode != http.StatusNoContent {
		t.Fatalf("expected one retry and success, calls=%d result=%+v", calls.Load(), result)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ = errors.Is
var _ = fmt.Sprint

func TestProbeURLRejectsRedirectOutsideAuthorizedHostnameBoundary(t *testing.T) {
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://outside.example.invalid/", http.StatusFound)
	}))
	defer inside.Close()

	_, err := ProbeURL(context.Background(), inside.URL, WebConfig{Concurrency: 1, Timeout: time.Second, MaxBodyBytes: 1024, MaxRedirects: 5}, inside.Client())
	if err == nil || !strings.Contains(err.Error(), "authorized hostname") {
		t.Fatalf("expected authorized-host redirect error, got %v", err)
	}
}
