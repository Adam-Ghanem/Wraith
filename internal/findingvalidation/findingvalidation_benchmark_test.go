package findingvalidation

import "testing"

func BenchmarkCompareNormalizedResponse(b *testing.B) {
	baseline := ResponseSnapshot{StatusCode: 200, ContentType: "text/html", Body: []byte("request 2026-08-19T10:00:00Z")}
	response := ResponseSnapshot{StatusCode: 500, ContentType: "text/html", Body: []byte("database syntax error")}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		_ = Compare(baseline, response, "canary")
	}
}
