package evidence

import (
	"strings"
	"testing"
	"time"
)

func TestNewFuzzObservationStoresOnlyRedactedStructuralMetadata(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	endpoint, err := NewEndpoint("project-a", "GET", "https://example.test/api/users?id=secret", now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewFuzzObservation("project-a", endpoint, FuzzObservationInput{Source: "fuzz.response", ObservedAt: now, MutationID: "minimal/one-char", MutationCategory: "boundary", SafetyClass: "generic", StatusCode: 500, ContentType: "application/json", ContentLength: 17, DurationMS: 12, Fingerprint: "0123456789abcdef", StatusChanged: true, ContentTypeEqual: true, LengthDelta: 4, ReflectionLocation: "body", ErrorClasses: []string{"server_error", "type_error"}, RedirectCount: 1})
	if err != nil || record.Kind != ObservationKindFuzz || !record.Redacted || strings.Contains(string(record.Payload), "secret") || strings.Contains(string(record.Payload), "password") || strings.Contains(string(record.Payload), "response_body") {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}
