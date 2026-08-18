package validation

import (
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"net/http"
	"testing"
	"time"
)

func BenchmarkRunDefaultValidators(b *testing.B) {
	ep, _ := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.test/", time.Unix(0, 0).UTC())
	in := Input{ProjectID: "project-a", Endpoint: ep, ObservedAt: time.Unix(0, 0).UTC(), StatusCode: 500, Headers: http.Header{"Server": {"nginx/1.2"}, "Set-Cookie": {"sid=opaque"}}, Body: []byte("panic: runtime error")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(in, DefaultValidators()); err != nil {
			b.Fatal(err)
		}
	}
}
