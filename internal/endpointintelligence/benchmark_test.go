package endpointintelligence

import "testing"

func BenchmarkParseOpenAPI(b *testing.B) {
	document := []byte(`{"openapi":"3.0.0","servers":[{"url":"https://api.example.test"}],"paths":{"/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}}}}`)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := ParseOpenAPI("project-a", document, DefaultOpenAPILimits()); err != nil {
			b.Fatal(err)
		}
	}
}
