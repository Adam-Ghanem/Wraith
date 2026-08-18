package jsanalysis

import (
	"strings"
	"testing"
)

func BenchmarkStaticAnalyzeSmall(b *testing.B) {
	benchmarkStaticAnalyze(b, []byte(`fetch("/api/users?id=1", {method:"POST", body: JSON.stringify({email:value})})`))
}

func BenchmarkStaticAnalyzeMedium(b *testing.B) {
	benchmarkStaticAnalyze(b, []byte(strings.Repeat(`axios.get("/api/users?id=1"); const route={path:"/users"};`, 300)))
}

func BenchmarkStaticAnalyzeMinified(b *testing.B) {
	benchmarkStaticAnalyze(b, []byte(strings.Repeat(`fetch("/api/x",{method:"GET"});new WebSocket("wss://x.test/s");`, 300)))
}

func benchmarkStaticAnalyze(b *testing.B, source []byte) {
	b.Helper()
	limits := DefaultStaticLimits()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := StaticAnalyze(StaticInput{SourceID: "benchmark:app.js", Body: source}, limits); err != nil {
			b.Fatal(err)
		}
	}
}
