package jsanalysis

import "testing"

func FuzzStaticAnalyzeNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`fetch("/api/users", {method:"GET"})`), []byte(`const =`), []byte("//# sourceMappingURL=app.js.map")} {
		f.Add(seed)
	}
	limits := DefaultStaticLimits()
	limits.MaxFileBytes = 256 << 10
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > limits.MaxFileBytes {
			return
		}
		_, _ = StaticAnalyze(StaticInput{SourceID: "fuzz:input.js", Body: source}, limits)
	})
}

func FuzzParseLocalSourceMapNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":3,"sources":["app.ts"],"mappings":"AAAA"}`))
	f.Add([]byte(`{`))
	limits := DefaultSourceMapLimits()
	limits.MaxBytes = 256 << 10
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > limits.MaxBytes {
			return
		}
		_, _ = ParseLocalSourceMap(data, limits)
	})
}
