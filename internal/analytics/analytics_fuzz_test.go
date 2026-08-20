package analytics

import (
	"testing"
	"time"
)

func FuzzBuildSnapshotRejectsMalformedOrSecretBearingInput(f *testing.F) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	f.Add("alpha", "a", int64(0), int64(0))
	f.Add("api_key_alpha", "b", int64(-1), int64(1))
	f.Fuzz(func(t *testing.T, projectID, marker string, regressionCount, unresolvedCount int64) {
		if len(projectID) > 600 || len(marker) > 80 || regressionCount < -1_000 || regressionCount > 1_000 || unresolvedCount < -1_000 || unresolvedCount > 1_000 {
			t.Skip()
		}
		record := newRecord(projectID, normalizedFuzzHex(marker), at, int(regressionCount), 0, 0, int(unresolvedCount), 1, 0, 0, 0)
		_, _ = BuildSnapshot(SnapshotInput{ProjectID: projectID, Window: Window{From: at, To: at}, AsOf: at, Records: []HistoricalRecord{record}})
	})
}

func normalizedFuzzHex(value string) string {
	if value == "" {
		return "a"
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "a"
		}
	}
	return value
}
