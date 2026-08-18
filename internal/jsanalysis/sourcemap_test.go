package jsanalysis

import "testing"

func TestParseLocalSourceMapReturnsSortedStructuralMetadata(t *testing.T) {
	summary, err := ParseLocalSourceMap([]byte(`{"version":3,"sources":["src/b.ts","src/a.ts","src/a.ts"],"mappings":"AAAA"}`), DefaultSourceMapLimits())
	if err != nil || summary.Version != 3 || summary.MappingsSize != 4 || len(summary.Sources) != 2 || summary.Sources[0] != "src/a.ts" {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	if _, err := ParseLocalSourceMap([]byte(`{"version":3,"sources":["ok"],"mappings":"`+string(make([]byte, 300<<10))+`"}`), DefaultSourceMapLimits()); err == nil {
		t.Fatal("expected oversized mappings rejection")
	}
}
