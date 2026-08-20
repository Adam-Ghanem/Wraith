package analytics

import (
	"testing"
	"time"
)

func TestBuildSnapshotAggregatesHistoricalTrendHealthAndLineageDeterministically(t *testing.T) {
	from := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	input := SnapshotInput{
		ProjectID: "alpha",
		Window:    Window{From: from, To: from.Add(72 * time.Hour)},
		AsOf:      from.Add(72 * time.Hour),
		Records: []HistoricalRecord{
			newRecord("alpha", "a", from, 3, 1, 2, 4, 12, 6, 60, 100),
			newRecord("alpha", "b", from.Add(24*time.Hour), 3, 1, 2, 4, 12, 6, 60, 100),
			newRecord("alpha", "c", from.Add(48*time.Hour), 1, 0, 0, 1, 10, 5, 80, 100),
			newRecord("alpha", "d", from.Add(72*time.Hour), 1, 0, 0, 1, 10, 5, 80, 100),
		},
	}
	first, err := BuildSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || first.Fingerprint == "" {
		t.Fatalf("snapshot fingerprint must be deterministic: first=%q second=%q", first.Fingerprint, second.Fingerprint)
	}
	if first.OverallTrend != TrendImproving {
		t.Fatalf("overall trend=%q, want improving", first.OverallTrend)
	}
	if first.Health.Index != 40 || first.Health.Classification != HealthDegraded {
		t.Fatalf("health=%+v, want degraded index 40", first.Health)
	}
	if first.DataQuality.Status != DataQualityComplete || first.DataQuality.ValidRecordCount != 4 || first.DataQuality.ExcludedRecordCount != 0 {
		t.Fatalf("data quality=%+v", first.DataQuality)
	}
	if got, want := first.Summary.RegressionCount, 8; got != want {
		t.Fatalf("regression count=%d, want %d", got, want)
	}
	if got, want := first.Summary.UnresolvedGovernanceCount, 10; got != want {
		t.Fatalf("unresolved count=%d, want %d", got, want)
	}
	if len(first.SourceFingerprints) != 4 || first.SourceFingerprints[0] >= first.SourceFingerprints[1] {
		t.Fatalf("source lineage not sorted: %v", first.SourceFingerprints)
	}
	if len(first.Anomalies) != 0 {
		t.Fatalf("unexpected anomalies: %+v", first.Anomalies)
	}
}

func TestBuildSnapshotMarksInsufficientHistoryWithoutFabricatingTrend(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	snapshot, err := BuildSnapshot(SnapshotInput{
		ProjectID: "alpha",
		Window:    Window{From: at.Add(-time.Hour), To: at},
		AsOf:      at,
		Records:   []HistoricalRecord{newRecord("alpha", "a", at, 0, 0, 0, 0, 1, 0, 0, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OverallTrend != TrendInsufficientData {
		t.Fatalf("trend=%q, want insufficient-data", snapshot.OverallTrend)
	}
	if snapshot.DataQuality.Status != DataQualityInsufficient {
		t.Fatalf("data quality=%q, want insufficient", snapshot.DataQuality.Status)
	}
	if !contains(snapshot.Limitations, "insufficient_history_for_trends") {
		t.Fatalf("limitations=%v", snapshot.Limitations)
	}
}

func TestBuildSnapshotRejectsCrossProjectAndInvalidWindow(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	base := SnapshotInput{ProjectID: "alpha", Window: Window{From: at, To: at.Add(time.Hour)}, AsOf: at.Add(time.Hour), Records: []HistoricalRecord{newRecord("beta", "a", at, 0, 0, 0, 0, 1, 0, 0, 0)}}
	if _, err := BuildSnapshot(base); err == nil {
		t.Fatal("expected cross-project record rejection")
	}
	base.Records[0] = newRecord("alpha", "a", at, 0, 0, 0, 0, 1, 0, 0, 0)
	base.Window = Window{From: at.Add(time.Hour), To: at}
	if _, err := BuildSnapshot(base); err == nil {
		t.Fatal("expected reversed window rejection")
	}
}

func TestBuildSnapshotRejectsDuplicateSourceFingerprintAcrossNonAdjacentRecords(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	duplicate := newRecord("alpha", "a", at, 0, 0, 0, 0, 1, 0, 0, 0)
	input := SnapshotInput{
		ProjectID: "alpha",
		Window:    Window{From: at, To: at.Add(2 * time.Hour)},
		AsOf:      at.Add(2 * time.Hour),
		Records: []HistoricalRecord{
			duplicate,
			newRecord("alpha", "b", at.Add(time.Hour), 0, 0, 0, 0, 1, 0, 0, 0),
			func() HistoricalRecord {
				copy := duplicate
				copy.Timestamp = at.Add(2 * time.Hour)
				return copy
			}(),
		},
	}
	if _, err := BuildSnapshot(input); err == nil {
		t.Fatal("expected duplicate source fingerprint rejection")
	}
}

func TestBuildSnapshotClassifiesContradictoryHistoryAndEmitsBoundedAnomaly(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	first := newRecord("alpha", "a", at, 1, 0, 0, 0, 1, 0, 0, 0)
	first.Limitations = []string{"source_contradiction"}
	snapshot, err := BuildSnapshot(SnapshotInput{
		ProjectID: "alpha",
		Window:    Window{From: at, To: at.Add(3 * time.Hour)},
		AsOf:      at.Add(3 * time.Hour),
		Records: []HistoricalRecord{
			first,
			newRecord("alpha", "b", at.Add(time.Hour), 1, 0, 0, 0, 1, 0, 0, 0),
			newRecord("alpha", "c", at.Add(2*time.Hour), 3, 0, 0, 0, 1, 0, 0, 0),
			newRecord("alpha", "d", at.Add(3*time.Hour), 3, 0, 0, 0, 1, 0, 0, 0),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataQuality.Status != DataQualityContradictory {
		t.Fatalf("data quality=%q, want contradictory", snapshot.DataQuality.Status)
	}
	if len(snapshot.Anomalies) != 1 || snapshot.Anomalies[0].Metric != "regressions" || snapshot.Anomalies[0].Observed != 6 || snapshot.Anomalies[0].Reference != 2 || snapshot.Anomalies[0].Threshold != 4 {
		t.Fatalf("anomalies=%+v", snapshot.Anomalies)
	}
}

func TestBuildSnapshotCarriesExplicitExcludedSourceAccounting(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	snapshot, err := BuildSnapshot(SnapshotInput{
		ProjectID:           "alpha",
		Window:              Window{From: at, To: at.Add(2 * time.Hour)},
		AsOf:                at.Add(2 * time.Hour),
		ExcludedSourceCount: 1,
		ExclusionReasons:    []string{"invalid_r18_comparison"},
		Records: []HistoricalRecord{
			newRecord("alpha", "a", at, 0, 0, 0, 0, 1, 0, 0, 0),
			newRecord("alpha", "b", at.Add(2*time.Hour), 0, 0, 0, 0, 1, 0, 0, 0),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataQuality.Status != DataQualityPartial || snapshot.DataQuality.ExcludedRecordCount != 1 || !contains(snapshot.DataQuality.ExclusionReasons, "invalid_r18_comparison") {
		t.Fatalf("data quality=%+v", snapshot.DataQuality)
	}
}

func TestBuildSnapshotRepresentsUnavailableHistoryExplicitly(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	snapshot, err := BuildSnapshot(SnapshotInput{ProjectID: "alpha", Window: Window{From: at.Add(-time.Hour), To: at}, AsOf: at, ExcludedSourceCount: 1, ExclusionReasons: []string{"no_verified_assessment_history"}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OverallTrend != TrendInsufficientData || snapshot.Health.Classification != HealthUnknown || snapshot.DataQuality.Status != DataQualityInsufficient || !contains(snapshot.Limitations, "no_verified_assessment_history") {
		t.Fatalf("unavailable snapshot=%+v", snapshot)
	}
}

func TestValidateSnapshotRejectsForgedDerivedMetric(t *testing.T) {
	at := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	snapshot, err := BuildSnapshot(SnapshotInput{ProjectID: "alpha", Window: Window{From: at, To: at.Add(time.Hour)}, AsOf: at.Add(time.Hour), Records: []HistoricalRecord{newRecord("alpha", "a", at, 1, 0, 0, 0, 1, 0, 0, 0), newRecord("alpha", "b", at.Add(time.Hour), 0, 0, 0, 0, 1, 0, 0, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateSnapshot(snapshot) {
		t.Fatal("expected canonical snapshot to validate")
	}
	snapshot.Summary.RegressionCount++
	if ValidateSnapshot(snapshot) {
		t.Fatal("expected forged snapshot rejection")
	}
}

func newRecord(projectID, marker string, at time.Time, regressions, policyFailures, staleEvidence, unresolved, endpoints, parameters, coverageNumerator, coverageDenominator int) HistoricalRecord {
	return HistoricalRecord{
		ProjectID:          projectID,
		Timestamp:          at,
		SourceFingerprint:  repeatHex(marker),
		RegressionCount:    regressions,
		PolicyFailureCount: policyFailures,
		Evidence:           EvidenceCounts{Stale: staleEvidence},
		Surface:            SurfaceCounts{Endpoints: endpoints, Parameters: parameters, CoverageDefinition: "known_surface", CoverageNumerator: coverageNumerator, CoverageDenominator: coverageDenominator},
		Governance:         GovernanceCounts{Unresolved: unresolved},
	}
}

func repeatHex(marker string) string {
	for len(marker) < 64 {
		marker += marker
	}
	return marker[:64]
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
