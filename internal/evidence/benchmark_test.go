package evidence

import (
	"fmt"
	"testing"
)

func BenchmarkCanonicalizeURL(b *testing.B) {
	for _, queryPairs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("query_pairs=%d", queryPairs), func(b *testing.B) {
			query := ""
			for index := 0; index < queryPairs; index++ {
				if index > 0 {
					query += "&"
				}
				query += fmt.Sprintf("k%03d=v%03d", queryPairs-index, index)
			}
			raw := "https://example.com/api?" + query
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, err := CanonicalizeURL(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
