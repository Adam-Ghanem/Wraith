package evidence

import (
	"strings"
	"testing"
	"time"
)

func TestNewInjectionObservationStoresOnlyBoundedSignalMetadata(t *testing.T) {
	endpoint, err := NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := NewParameter("alpha", endpoint, ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := NewInjectionObservation("alpha", endpoint, parameter, InjectionObservationInput{RunID: "run-1", TestID: "test-1", InjectionClass: "sql", SignalType: "error", Confidence: "possible", Fingerprint: "abc123", ObservedAt: time.Unix(2, 0), StatusCode: 500, ContentType: "text/html", ContentLength: 42, DurationMS: 2})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Source != "injection.r11.3.result" || !observation.Redacted || observation.Kind != ObservationKindFuzz {
		t.Fatalf("observation=%#v", observation)
	}
	if strings.Contains(string(observation.Payload), "'") || strings.Contains(strings.ToLower(string(observation.Payload)), "token") {
		t.Fatalf("payload leaked=%s", observation.Payload)
	}
}

func TestNewInjectionObservationRejectsSecretLikeTestMetadata(t *testing.T) {
	endpoint, _ := NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	parameter, _ := NewParameter("alpha", endpoint, ParameterLocationQuery, "q", time.Unix(1, 0))
	if _, err := NewInjectionObservation("alpha", endpoint, parameter, InjectionObservationInput{RunID: "Bearer token", TestID: "test-1", InjectionClass: "sql", SignalType: "error", Confidence: "possible", Fingerprint: "abc", ObservedAt: time.Unix(2, 0), StatusCode: 500, ContentLength: 1}); err == nil {
		t.Fatal("expected secret metadata rejection")
	}
}
