package cli

import "testing"

func BenchmarkT6OutboundBlockLegacyHTTP(b *testing.B) {
	args := []string{"http", "https://example.test/secret"}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := t6OutboundBlock(args); err == nil {
			b.Fatal("legacy HTTP command was not blocked")
		}
	}
}
