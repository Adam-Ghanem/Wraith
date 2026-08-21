package dataclassification

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyRedactsSecretHeaderWithoutRetainingValue(t *testing.T) {
	decision, err := Classify(Input{Kind: KindHeader, Name: "Authorization", Value: "Bearer should-never-appear", Destination: DestinationEvidence})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Level != LevelSecret || decision.Action != ActionRedact || !decision.Redacted || decision.Value != RedactedValue {
		t.Fatalf("decision=%+v", decision)
	}
	if strings.Contains(decision.Value, "should-never-appear") {
		t.Fatalf("secret leaked through decision: %+v", decision)
	}
}

func TestSanitizeURLRejectsUserInfoAndRedactsSensitiveQueryValues(t *testing.T) {
	if _, _, err := SanitizeURL("https://user:password@example.test/private"); !errors.Is(err, ErrCredentialBearingURL) {
		t.Fatalf("userinfo error=%v", err)
	}
	safe, decision, err := SanitizeURL("https://example.test/search?query=visible&access_token=must-not-persist")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Level != LevelSecret || decision.Action != ActionRedact || !decision.Redacted {
		t.Fatalf("query decision=%+v", decision)
	}
	if strings.Contains(safe, "must-not-persist") || !strings.Contains(safe, "access_token=REDACTED") || !strings.Contains(safe, "query=visible") {
		t.Fatalf("unsafe URL projection=%q", safe)
	}
}

func TestSanitizeJSONRedactsSecretFieldsWithinLimits(t *testing.T) {
	safe, decision, err := SanitizeJSON([]byte(`{"nested":{"refresh_token":"do-not-store"},"name":"retained"}`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Level != LevelSecret || decision.Action != ActionRedact || !decision.Redacted {
		t.Fatalf("decision=%+v", decision)
	}
	if strings.Contains(string(safe), "do-not-store") || !strings.Contains(string(safe), RedactedValue) || !strings.Contains(string(safe), "retained") {
		t.Fatalf("unsafe JSON projection=%s", safe)
	}
}

func TestSafeReferenceRejectsSecretMaterialWithoutEchoingIt(t *testing.T) {
	err := ValidateSafeReference("Bearer do-not-echo")
	if !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("reference error=%v", err)
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("secret leaked in error=%v", err)
	}
}
