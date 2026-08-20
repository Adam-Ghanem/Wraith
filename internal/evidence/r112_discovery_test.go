package evidence

import (
	"testing"
	"time"
)

func TestNewDiscoveryObservationRecordsBoundedR112VerificationMetadata(t *testing.T) {
	endpoint, err := NewEndpoint("alpha", "HEAD", "https://example.test/openapi.json", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := NewDiscoveryObservation("alpha", endpoint, DiscoveryObservationInput{CandidateID: "candidate-1", CandidateType: "documentation", VerificationStatus: "found", ObservedAt: time.Unix(2, 0), StatusCode: 200, ContentType: "application/json", ContentLength: 12, DurationMS: 3, RedirectCount: 0})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Source != "smart-discovery.r11.2.verify" || observation.Kind != ObservationKindContent || !observation.Redacted {
		t.Fatalf("observation=%#v", observation)
	}
	if string(observation.Payload) == "" || containsSensitive(string(observation.Payload)) {
		t.Fatalf("unexpected payload=%s", observation.Payload)
	}
}

func TestNewDiscoveryObservationRejectsSecretLikeCandidateMetadata(t *testing.T) {
	endpoint, err := NewEndpoint("alpha", "HEAD", "https://example.test/openapi.json", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiscoveryObservation("alpha", endpoint, DiscoveryObservationInput{CandidateID: "Bearer token", CandidateType: "documentation", VerificationStatus: "found", ObservedAt: time.Unix(2, 0), StatusCode: 200, ContentLength: 1}); err == nil {
		t.Fatal("expected secret-like candidate metadata rejection")
	}
}
