package analytics

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkBuildSnapshot(b *testing.B) {
	for _, size := range []int{8, MaxRecords} {
		b.Run(fmt.Sprintf("records_%d", size), func(b *testing.B) {
			at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
			records := make([]HistoricalRecord, size)
			for index := range records {
				records[index] = newRecord("alpha", fmt.Sprintf("%x", index+10), at.Add(time.Duration(index)*time.Minute), index%3, index%2, index%2, index%5, index+1, index, 50, 100)
			}
			input := SnapshotInput{ProjectID: "alpha", Window: Window{From: at, To: at.Add(time.Duration(size) * time.Minute)}, AsOf: at.Add(time.Duration(size) * time.Minute), Records: records}
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, err := BuildSnapshot(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
