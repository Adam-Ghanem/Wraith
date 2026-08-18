package contentdiscovery

import (
	"net/http"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func FuzzNormalizeR75Path(f *testing.F) {
	for _, seed := range []string{"admin", "/api/v1", "../escape", "https://outside.test", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		path, err := normalizeR75Path(raw, 512)
		if err == nil && (path == "" || path[0] != '/' || path == r75BaselinePath) {
			t.Fatalf("accepted invalid normalized path %q from %q", path, raw)
		}
	})
}

func FuzzNormalizeR75Hostname(f *testing.F) {
	for _, seed := range []string{"example.test", "ADMIN.example.test", "bad/value", "a..b", "-bad.test"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		hostname, err := normalizeR75Hostname(raw)
		if err == nil && (hostname == "" || len(hostname) > 253) {
			t.Fatalf("accepted invalid normalized hostname %q from %q", hostname, raw)
		}
	})
}

func BenchmarkFingerprintR75(b *testing.B) {
	response := httpengine.Response{StatusCode: http.StatusOK, ContentType: "text/html; charset=utf-8", ContentLength: 4096, Body: make([]byte, 4096)}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = FingerprintR75(response)
	}
}

func BenchmarkBuildR75Plan(b *testing.B) {
	entries := []string{"/admin", "/api", "/docs", "/health", "/static"}
	limits := DefaultR75Limits()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := BuildR75Plan("project-a", "https://example.test/", entries, limits); err != nil {
			b.Fatal(err)
		}
	}
}
