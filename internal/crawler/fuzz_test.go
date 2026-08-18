package crawler

import "testing"

func FuzzExtractDocumentNeverPanics(f *testing.F) {
	f.Add("https://example.com/", "<a href='/a'>a</a>")
	f.Add("https://example.com/", "<form><input name='q'></form><meta http-equiv='refresh' content='0;url=/next'>")
	f.Fuzz(func(t *testing.T, base, body string) { _, _ = ExtractDocument(base, []byte(body)) })
}
