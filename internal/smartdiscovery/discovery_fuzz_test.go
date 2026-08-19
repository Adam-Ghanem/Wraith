package smartdiscovery

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
)

func FuzzBuildNeverPanicsOnUntrustedCandidateText(f *testing.F) {
	f.Add("/api/v1/users", "javascript")
	f.Add("/../etc/passwd", "manual")
	f.Add("Bearer abc.def.ghi", "javascript")
	f.Fuzz(func(t *testing.T, value, sourceText string) {
		source := DiscoverySource(sourceText)
		if source == "" {
			source = SourceManual
		}
		_, _ = Build(Input{ProjectID: "alpha", BaseURL: "https://example.test", Inventory: endpointintelligence.Inventory{ProjectID: "alpha"}, Seeds: []Seed{{Type: CandidatePath, Value: value, Source: source, EvidenceID: "fuzz"}}, Limits: DefaultLimits()})
	})
}

func FuzzNormalizeWordlistEntryNeverReturnsSensitivePath(f *testing.F) {
	f.Add("docs")
	f.Add(".env")
	f.Fuzz(func(t *testing.T, value string) {
		path, err := normalizeWordlistEntry(value, 512)
		if err == nil && sensitivePath(path) {
			t.Fatalf("accepted sensitive path %q", path)
		}
	})
}
