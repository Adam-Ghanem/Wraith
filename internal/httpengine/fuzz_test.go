package httpengine

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func FuzzRequestURLNeverPanics(f *testing.F) {
	for _, seed := range []string{"https://example.com/", "http://[::1]/", "https://example.com/%2e%2e/x", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		engine := NewEngine(Config{Gateway: fakeGateway{deny: true}})
		_, _ = engine.Do(context.Background(), Request{ProjectID: "fuzz", Method: "GET", URL: raw})
	})
}

func FuzzDestinationValidationNeverPanics(f *testing.F) {
	for _, seed := range []string{"127.0.0.1", "::1", "2001:db8::1", "not-an-ip"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if address, err := netip.ParseAddr(raw); err == nil {
			_ = (DestinationPolicy{}).Validate(address)
		}
	})
}

func FuzzRedirectResolutionNeverPanics(f *testing.F) {
	for _, seed := range [][2]string{{"https://example.com/a", "/b"}, {"https://example.com/a", "https://other.example.com/"}, {"https://example.com/a", "%"}, {"", ""}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, base, location string) {
		_, _ = responseURL(base, location)
	})
}

func FuzzHeaderProcessingNeverPanics(f *testing.F) {
	for _, seed := range [][2]string{{"Authorization", "opaque"}, {"Set-Cookie", "session=opaque"}, {"Content-Type", "application/json"}, {"\x00", "\x00"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, key, value string) {
		_ = headerMap(http.Header{key: []string{value}})
	})
}

func FuzzRequestConfigurationNeverPanics(f *testing.F) {
	for _, seed := range []string{"", "http://proxy.invalid", "socks5://proxy.invalid", "https://user:pass@proxy.invalid:8443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, proxyURL string) {
		engine := NewEngine(Config{Gateway: fakeGateway{deny: true}, ProxyURL: proxyURL})
		_, _ = engine.Do(context.Background(), Request{ProjectID: "fuzz", Method: http.MethodGet, URL: "https://example.com/"})
	})
}

var _ policy.Action
