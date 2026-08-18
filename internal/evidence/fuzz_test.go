package evidence

import "testing"

func FuzzCanonicalizeURLNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/",
		"https://example.com/api?b=2&a=1",
		"https://example.com@evil.com",
		"https://[2001:db8::1]/v1",
		"https://example.com/%2e%2e/admin",
		"\x00\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = CanonicalizeURL(raw)
	})
}

func FuzzNewWebAssetNeverPanics(f *testing.F) {
	for _, seed := range []string{"https://example.com/", "https://example.com/app.js", "not-a-url", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = NewWebAsset("fuzz-project", AssetKindURL, raw, fixedNow())
		_, _ = NewWebAsset("fuzz-project", AssetKindJavaScript, raw, fixedNow())
	})
}
