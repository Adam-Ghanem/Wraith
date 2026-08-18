package httpengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func BenchmarkRequestCreation(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/resource", nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTargetValidation(b *testing.B) {
	for index := 0; index < b.N; index++ {
		if _, err := policy.ParseTarget("https://api.example.com:8443/v1/assets"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDestinationValidation(b *testing.B) {
	destinationPolicy := DestinationPolicy{}
	address := netip.MustParseAddr("8.8.8.8")
	for index := 0; index < b.N; index++ {
		if err := destinationPolicy.Validate(address); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHeaderRedaction(b *testing.B) {
	endpoint, err := evidence.NewEndpoint("project-a", http.MethodGet, "https://example.com/", time.Unix(0, 0).UTC())
	if err != nil {
		b.Fatal(err)
	}
	input := evidence.HTTPObservationInput{Source: "benchmark", ObservedAt: time.Unix(0, 0).UTC(), StatusCode: http.StatusOK, ResponseHeaders: map[string]string{"Authorization": "opaque", "Set-Cookie": "session=opaque", "Content-Type": "application/json"}}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := evidence.NewHTTPObservation("project-a", endpoint, input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResponseMetadataProcessing(b *testing.B) {
	headers := http.Header{"Content-Type": []string{"application/json"}, "Server": []string{"wraith-lab"}, "Set-Cookie": []string{"session=opaque"}}
	for index := 0; index < b.N; index++ {
		metadata := headerMap(headers)
		if len(metadata) != 3 {
			b.Fatal("unexpected metadata size")
		}
	}
}

func BenchmarkConnectionReuse(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	engine := NewEngine(Config{Gateway: fakeGateway{}, DestinationPolicy: DestinationPolicy{AllowPrivate: true}})
	request := Request{ProjectID: "project-a", Method: http.MethodGet, URL: server.URL}
	if _, err := engine.Do(context.Background(), request); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := engine.Do(context.Background(), request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRateLimiterWait(b *testing.B) {
	limiter := NewRateLimiter(time.Nanosecond)
	ctx := context.Background()
	for index := 0; index < b.N; index++ {
		if err := limiter.Wait(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
