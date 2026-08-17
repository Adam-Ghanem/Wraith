package enum

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCertificateNamesFiltersWildcardsAndForeignDomains(t *testing.T) {
	body := []byte(`[{"name_value":"api.example.com\n*.api.example.com\nother.example.net"},{"name_value":"WWW.EXAMPLE.COM"}]`)
	got, err := ParseCRTNames(body, "example.com")
	if err != nil {
		t.Fatalf("parse CRT names: %v", err)
	}
	want := []string{"api.example.com", "www.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestCRTSourceUsesBoundedHTTPAndParsesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("expected JSON output query, got %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"api.example.com"}]`))
	}))
	defer server.Close()

	source := CRTSource{BaseURL: server.URL, Client: server.Client(), Timeout: time.Second, MaxBytes: 1024}
	results, err := source.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("enumerate CRT: %v", err)
	}
	if len(results) != 1 || results[0].Subdomain != "api.example.com" || results[0].Source != "crt.sh" {
		t.Fatalf("unexpected CRT results: %+v", results)
	}
}

func TestEnumerateSourcesContinuesWhenOptionalSourceFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"api.example.com"}]`))
	}))
	defer server.Close()

	enumerator := Enumerator{
		CRT: CRTSource{BaseURL: server.URL, Client: server.Client(), Timeout: time.Second, MaxBytes: 1024},
		DNS: NewDNSBruteForcer(&fakeResolver{answers: map[string][]string{"www.example.com": {"192.0.2.11"}}}, []string{"www"}, DNSConfig{Concurrency: 1, PerSecond: 20, Timeout: time.Second}),
	}
	results, errs := enumerator.Enumerate(context.Background(), "example.com")
	if len(results) != 2 {
		t.Fatalf("expected CRT and DNS results, got %+v", results)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no source errors, got %+v", errs)
	}
}
