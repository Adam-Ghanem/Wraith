package httpengine

import (
	"context"
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

var _ policy.Action
