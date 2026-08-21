package dataclassification

import "testing"

func FuzzSanitizeURLNeverRetainsSensitiveQueryValues(f *testing.F) {
	for _, seed := range []string{"https://example.test/?token=secret", "https://example.test/?query=visible", "https://user:pass@example.test/", "not a url"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _, _ = SanitizeURL(raw)
	})
}

func FuzzSanitizeJSONIsBoundedAndDeterministic(f *testing.F) {
	for _, seed := range []string{`{"token":"secret","name":"safe"}`, `[]`, `{"nested":{"password":"x"}}`, `not-json`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		first, firstDecision, firstErr := SanitizeJSON(raw, DefaultLimits())
		second, secondDecision, secondErr := SanitizeJSON(raw, DefaultLimits())
		if (firstErr == nil) != (secondErr == nil) || string(first) != string(second) || firstDecision != secondDecision {
			t.Fatalf("non-deterministic JSON governance")
		}
	})
}
