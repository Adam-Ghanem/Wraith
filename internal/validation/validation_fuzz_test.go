package validation

import (
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"net/http"
	"testing"
	"time"
)

func FuzzRunPassiveValidators(f *testing.F) {
	f.Add("nginx/1.2", "panic: runtime error")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, server, body string) {
		ep, err := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.test/", time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = Run(Input{ProjectID: "project-a", Endpoint: ep, ObservedAt: time.Unix(0, 0).UTC(), StatusCode: 500, Headers: http.Header{"Server": {server}}, Body: []byte(body)}, DefaultValidators())
	})
}
