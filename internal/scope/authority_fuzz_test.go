package scope

import "testing"

func FuzzParseTargetNeverPanics(f *testing.F) {
	f.Add("https://example.com/path")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = ParseTarget(raw) })
}
