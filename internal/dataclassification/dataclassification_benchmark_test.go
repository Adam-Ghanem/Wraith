package dataclassification

import "testing"

func BenchmarkSanitizeJSON(b *testing.B) {
	raw := []byte(`{"nested":{"access_token":"secret","name":"retained"},"items":[{"password":"secret"},{"value":"safe"}]}`)
	limits := DefaultLimits()
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, _, err := SanitizeJSON(raw, limits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClassifyHeader(b *testing.B) {
	input := Input{Kind: KindHeader, Name: "Authorization", Value: "Bearer secret", Destination: DestinationEvidence}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := Classify(input); err != nil {
			b.Fatal(err)
		}
	}
}
