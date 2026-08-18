package crawler

import "testing"

func BenchmarkExtractDocument(b *testing.B) {
	body := []byte(`<html><head><base href="/app/"></head><body><a href="one#x">one</a><script src="app.js"></script><form action="/search"><input name="q"></form></body></html>`)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := ExtractDocument("https://example.com/", body); err != nil {
			b.Fatal(err)
		}
	}
}
