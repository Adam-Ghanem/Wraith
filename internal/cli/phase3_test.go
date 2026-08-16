package cli

import "testing"

func TestParseScanOptionsAcceptsPhase3SkipFlags(t *testing.T) {
	options, err := parseScanOptions([]string{"scan", "-d", "example.com", "--authorized", "--skip-content-discovery", "--skip-js-analysis"})
	if err != nil {
		t.Fatalf("parse Phase 3 flags: %v", err)
	}
	if !options.SkipContentDiscovery || !options.SkipJSAnalysis {
		t.Fatalf("skip flags were not retained: %+v", options)
	}
}
