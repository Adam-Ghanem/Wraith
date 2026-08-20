// Package analytics derives deterministic, bounded historical intelligence from
// already validated project-local source records. It performs no I/O.
package analytics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion     = "r21.v1"
	MaxRecords        = 256
	MaxWindowDuration = 366 * 24 * time.Hour
)

type Trend string

const (
	TrendImproving        Trend = "improving"
	TrendStable           Trend = "stable"
	TrendDegrading        Trend = "degrading"
	TrendInsufficientData Trend = "insufficient-data"
)

type HealthClassification string

const (
	HealthHealthy  HealthClassification = "healthy"
	HealthDegraded HealthClassification = "degraded"
	HealthFailed   HealthClassification = "failed"
	HealthUnknown  HealthClassification = "unknown"
)

type DataQualityStatus string

const (
	DataQualityComplete      DataQualityStatus = "complete"
	DataQualityPartial       DataQualityStatus = "partial"
	DataQualityInsufficient  DataQualityStatus = "insufficient"
	DataQualityContradictory DataQualityStatus = "contradictory"
)

type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type EvidenceCounts struct {
	Fresh         int `json:"fresh"`
	Stale         int `json:"stale"`
	Contradictory int `json:"contradictory"`
	Incomplete    int `json:"incomplete"`
	Unsupported   int `json:"unsupported"`
	Reproducible  int `json:"reproducible"`
}

type SurfaceCounts struct {
	Endpoints           int    `json:"endpoints"`
	Parameters          int    `json:"parameters"`
	CoverageDefinition  string `json:"coverage_definition,omitempty"`
	CoverageNumerator   int    `json:"coverage_numerator"`
	CoverageDenominator int    `json:"coverage_denominator"`
}

type GovernanceCounts struct {
	Recommended  int `json:"recommended"`
	Acknowledged int `json:"acknowledged"`
	Accepted     int `json:"accepted"`
	Deferred     int `json:"deferred"`
	Rejected     int `json:"rejected"`
	Completed    int `json:"completed"`
	Expired      int `json:"expired"`
	Unresolved   int `json:"unresolved"`
}

type HistoricalRecord struct {
	ProjectID             string           `json:"project_id"`
	Timestamp             time.Time        `json:"timestamp"`
	SourceFingerprint     string           `json:"source_fingerprint"`
	SnapshotFingerprint   string           `json:"snapshot_fingerprint,omitempty"`
	ComparisonFingerprint string           `json:"comparison_fingerprint,omitempty"`
	EvaluationFingerprint string           `json:"evaluation_fingerprint,omitempty"`
	RegressionCount       int              `json:"regression_count"`
	PolicyFailureCount    int              `json:"policy_failure_count"`
	Evidence              EvidenceCounts   `json:"evidence"`
	Surface               SurfaceCounts    `json:"surface"`
	Governance            GovernanceCounts `json:"governance"`
	Limitations           []string         `json:"limitations,omitempty"`
}

type SnapshotInput struct {
	ProjectID           string
	Window              Window
	AsOf                time.Time
	Records             []HistoricalRecord
	ExcludedSourceCount int
	ExclusionReasons    []string
}

type MetricTrend struct {
	Metric      string `json:"metric"`
	Trend       Trend  `json:"trend"`
	Previous    int    `json:"previous"`
	Current     int    `json:"current"`
	SampleCount int    `json:"sample_count"`
}

type Anomaly struct {
	Metric    string `json:"metric"`
	Observed  int    `json:"observed"`
	Reference int    `json:"reference"`
	Threshold int    `json:"threshold"`
	Reason    string `json:"reason"`
}

type AssessmentHealth struct {
	Index          int                  `json:"index"`
	Classification HealthClassification `json:"classification"`
	Dimensions     []string             `json:"dimensions"`
	Limitations    []string             `json:"limitations"`
}

type DataQuality struct {
	Status              DataQualityStatus `json:"status"`
	SourceCount         int               `json:"source_count"`
	ValidRecordCount    int               `json:"valid_record_count"`
	ExcludedRecordCount int               `json:"excluded_record_count"`
	ExclusionReasons    []string          `json:"exclusion_reasons"`
	Limitations         []string          `json:"limitations"`
}

type Summary struct {
	RecordCount               int              `json:"record_count"`
	RegressionCount           int              `json:"regression_count"`
	PolicyFailureCount        int              `json:"policy_failure_count"`
	Evidence                  EvidenceCounts   `json:"evidence"`
	Surface                   SurfaceCounts    `json:"surface"`
	Governance                GovernanceCounts `json:"governance"`
	UnresolvedGovernanceCount int              `json:"unresolved_governance_count"`
}

type AnalyticsSnapshot struct {
	SchemaVersion      string           `json:"schema_version"`
	ProjectID          string           `json:"project"`
	GeneratedAt        time.Time        `json:"generated_at"`
	Window             Window           `json:"window"`
	SourceFingerprints []string         `json:"source_fingerprints"`
	Summary            Summary          `json:"summary"`
	Trends             []MetricTrend    `json:"trends"`
	OverallTrend       Trend            `json:"overall_trend"`
	Anomalies          []Anomaly        `json:"anomalies"`
	Health             AssessmentHealth `json:"health"`
	DataQuality        DataQuality      `json:"data_quality"`
	Limitations        []string         `json:"limitations"`
	Fingerprint        string           `json:"fingerprint"`
}

func BuildSnapshot(input SnapshotInput) (AnalyticsSnapshot, error) {
	if !validInput(input) {
		return AnalyticsSnapshot{}, errors.New("invalid analytics snapshot input")
	}
	input.ExclusionReasons = normalizeStrings(input.ExclusionReasons)
	records := append([]HistoricalRecord{}, input.Records...)
	for index := range records {
		records[index].Timestamp = records[index].Timestamp.UTC()
		records[index].Limitations = normalizeStrings(records[index].Limitations)
		if !validRecord(records[index], input.ProjectID, input.Window) {
			return AnalyticsSnapshot{}, errors.New("invalid or cross-project historical analytics record")
		}
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].Timestamp.Equal(records[right].Timestamp) {
			return records[left].SourceFingerprint < records[right].SourceFingerprint
		}
		return records[left].Timestamp.Before(records[right].Timestamp)
	})
	if !uniqueSources(records) {
		return AnalyticsSnapshot{}, errors.New("duplicate historical analytics source")
	}

	snapshot := AnalyticsSnapshot{
		SchemaVersion:      SchemaVersion,
		ProjectID:          strings.TrimSpace(input.ProjectID),
		GeneratedAt:        input.AsOf.UTC(),
		Window:             normalizeWindow(input.Window),
		SourceFingerprints: sourceFingerprints(records),
		Summary:            summarize(records),
		Limitations:        normalizeStrings(append(collectLimitations(records), input.ExclusionReasons...)),
	}
	snapshot.Trends = deriveTrends(records)
	snapshot.OverallTrend = overallTrend(snapshot.Trends)
	snapshot.Anomalies = deriveAnomalies(snapshot.Trends)
	currentUnresolved := 0
	if len(records) > 0 {
		currentUnresolved = records[len(records)-1].Governance.Unresolved
	}
	snapshot.Health = deriveHealth(snapshot.Summary, currentUnresolved, len(records) > 0)
	snapshot.DataQuality = deriveDataQuality(records, input.ExcludedSourceCount, input.ExclusionReasons, snapshot.Limitations)
	if snapshot.OverallTrend == TrendInsufficientData {
		snapshot.Limitations = append(snapshot.Limitations, "insufficient_history_for_trends")
	}
	snapshot.Limitations = normalizeStrings(snapshot.Limitations)
	snapshot.DataQuality.Limitations = normalizeStrings(append(snapshot.DataQuality.Limitations, snapshot.Limitations...))
	snapshot.Fingerprint = snapshotFingerprint(snapshot)
	return snapshot, nil
}

// ValidateSnapshot verifies bounded canonical derived analytics content. Storage
// adapters additionally recompute verified source history before serving a cache.
func ValidateSnapshot(snapshot AnalyticsSnapshot) bool {
	if snapshot.SchemaVersion != SchemaVersion || !validIdentifier(snapshot.ProjectID) || snapshot.GeneratedAt.IsZero() || !validWindow(snapshot.Window) || !validTrend(snapshot.OverallTrend) || !validDataQuality(snapshot.DataQuality) || !validHealth(snapshot.Health) || !validSummary(snapshot.Summary) || !validFingerprint(snapshot.Fingerprint) || !sortedUniqueFingerprints(snapshot.SourceFingerprints) || !sortedUniqueStrings(snapshot.Limitations) || !validTrends(snapshot.Trends) || !validAnomalies(snapshot.Anomalies) {
		return false
	}
	return snapshot.Fingerprint == snapshotFingerprint(snapshot)
}

func validInput(input SnapshotInput) bool {
	window := normalizeWindow(input.Window)
	if !validIdentifier(input.ProjectID) || input.AsOf.IsZero() || !validWindow(window) || len(input.Records) > MaxRecords || len(input.Records)+input.ExcludedSourceCount == 0 || input.ExcludedSourceCount < 0 || input.ExcludedSourceCount > MaxRecords {
		return false
	}
	for _, reason := range input.ExclusionReasons {
		if !validIdentifier(reason) {
			return false
		}
	}
	return true
}

func validWindow(window Window) bool {
	return !window.From.IsZero() && !window.To.IsZero() && !window.From.After(window.To) && window.To.Sub(window.From) <= MaxWindowDuration
}

func validSummary(value Summary) bool {
	return value.RecordCount >= 0 && value.RegressionCount >= 0 && value.PolicyFailureCount >= 0 && value.UnresolvedGovernanceCount >= 0 && validEvidence(value.Evidence) && validSurface(value.Surface) && validGovernance(value.Governance)
}

func validTrend(value Trend) bool {
	return value == TrendImproving || value == TrendStable || value == TrendDegrading || value == TrendInsufficientData
}

func validTrends(values []MetricTrend) bool {
	if len(values) != 5 {
		return false
	}
	for _, value := range values {
		if !validIdentifier(value.Metric) || !validTrend(value.Trend) || value.Previous < 0 || value.Current < 0 || value.SampleCount < 0 {
			return false
		}
	}
	return true
}

func validAnomalies(values []Anomaly) bool {
	for index, value := range values {
		if !validIdentifier(value.Metric) || !validIdentifier(value.Reason) || value.Observed < 0 || value.Reference < 0 || value.Threshold < 0 || (index > 0 && values[index-1].Metric >= value.Metric) {
			return false
		}
	}
	return true
}

func validHealth(value AssessmentHealth) bool {
	return value.Index >= 0 && value.Index <= 100 && (value.Classification == HealthHealthy || value.Classification == HealthDegraded || value.Classification == HealthFailed || value.Classification == HealthUnknown) && sortedUniqueStrings(value.Dimensions) && sortedUniqueStrings(value.Limitations)
}

func validDataQuality(value DataQuality) bool {
	return (value.Status == DataQualityComplete || value.Status == DataQualityPartial || value.Status == DataQualityInsufficient || value.Status == DataQualityContradictory) && value.SourceCount >= 0 && value.ValidRecordCount >= 0 && value.ExcludedRecordCount >= 0 && value.SourceCount == value.ValidRecordCount+value.ExcludedRecordCount && sortedUniqueStrings(value.ExclusionReasons) && sortedUniqueStrings(value.Limitations)
}

func validRecord(record HistoricalRecord, projectID string, window Window) bool {
	if record.ProjectID != strings.TrimSpace(projectID) || record.Timestamp.IsZero() || record.Timestamp.Before(window.From) || record.Timestamp.After(window.To) || !validFingerprint(record.SourceFingerprint) || !validOptionalFingerprint(record.SnapshotFingerprint) || !validOptionalFingerprint(record.ComparisonFingerprint) || !validOptionalFingerprint(record.EvaluationFingerprint) || record.RegressionCount < 0 || record.PolicyFailureCount < 0 || !validEvidence(record.Evidence) || !validSurface(record.Surface) || !validGovernance(record.Governance) {
		return false
	}
	for _, limitation := range record.Limitations {
		if !validIdentifier(limitation) {
			return false
		}
	}
	return true
}

func validEvidence(value EvidenceCounts) bool {
	return value.Fresh >= 0 && value.Stale >= 0 && value.Contradictory >= 0 && value.Incomplete >= 0 && value.Unsupported >= 0 && value.Reproducible >= 0
}

func validSurface(value SurfaceCounts) bool {
	return value.Endpoints >= 0 && value.Parameters >= 0 && value.CoverageNumerator >= 0 && value.CoverageDenominator >= 0 && value.CoverageNumerator <= value.CoverageDenominator && (value.CoverageDefinition == "" || validIdentifier(value.CoverageDefinition))
}

func validGovernance(value GovernanceCounts) bool {
	return value.Recommended >= 0 && value.Acknowledged >= 0 && value.Accepted >= 0 && value.Deferred >= 0 && value.Rejected >= 0 && value.Completed >= 0 && value.Expired >= 0 && value.Unresolved >= 0
}

func summarize(records []HistoricalRecord) Summary {
	summary := Summary{RecordCount: len(records)}
	for _, record := range records {
		summary.RegressionCount += record.RegressionCount
		summary.PolicyFailureCount += record.PolicyFailureCount
		summary.Evidence = addEvidence(summary.Evidence, record.Evidence)
		summary.Governance = addGovernance(summary.Governance, record.Governance)
		summary.UnresolvedGovernanceCount += record.Governance.Unresolved
	}
	if len(records) > 0 {
		summary.Surface = records[len(records)-1].Surface
	}
	return summary
}

func deriveTrends(records []HistoricalRecord) []MetricTrend {
	if len(records) < 2 {
		return []MetricTrend{
			{Metric: "regressions", Trend: TrendInsufficientData, SampleCount: len(records)},
			{Metric: "policy_failures", Trend: TrendInsufficientData, SampleCount: len(records)},
			{Metric: "stale_evidence", Trend: TrendInsufficientData, SampleCount: len(records)},
			{Metric: "governance_backlog", Trend: TrendInsufficientData, SampleCount: len(records)},
			{Metric: "surface_coverage", Trend: TrendInsufficientData, SampleCount: len(records)},
		}
	}
	middle := len(records) / 2
	previous, current := records[:middle], records[middle:]
	trends := []MetricTrend{
		newLowerBetterTrend("regressions", sumRecords(previous, func(record HistoricalRecord) int { return record.RegressionCount }), sumRecords(current, func(record HistoricalRecord) int { return record.RegressionCount }), len(records)),
		newLowerBetterTrend("policy_failures", sumRecords(previous, func(record HistoricalRecord) int { return record.PolicyFailureCount }), sumRecords(current, func(record HistoricalRecord) int { return record.PolicyFailureCount }), len(records)),
		newLowerBetterTrend("stale_evidence", sumRecords(previous, func(record HistoricalRecord) int { return record.Evidence.Stale + record.Evidence.Contradictory }), sumRecords(current, func(record HistoricalRecord) int { return record.Evidence.Stale + record.Evidence.Contradictory }), len(records)),
		newLowerBetterTrend("governance_backlog", sumRecords(previous, func(record HistoricalRecord) int { return record.Governance.Unresolved }), sumRecords(current, func(record HistoricalRecord) int { return record.Governance.Unresolved }), len(records)),
		coverageTrend(previous, current, len(records)),
	}
	return trends
}

func coverageTrend(previous, current []HistoricalRecord, samples int) MetricTrend {
	prior, recent := previous[len(previous)-1].Surface, current[len(current)-1].Surface
	metric := MetricTrend{Metric: "surface_coverage", SampleCount: samples}
	if prior.CoverageDefinition == "" || prior.CoverageDefinition != recent.CoverageDefinition || prior.CoverageDenominator == 0 || recent.CoverageDenominator == 0 {
		metric.Trend = TrendInsufficientData
		return metric
	}
	metric.Previous = prior.CoverageNumerator * 100 / prior.CoverageDenominator
	metric.Current = recent.CoverageNumerator * 100 / recent.CoverageDenominator
	switch {
	case metric.Current > metric.Previous:
		metric.Trend = TrendImproving
	case metric.Current < metric.Previous:
		metric.Trend = TrendDegrading
	default:
		metric.Trend = TrendStable
	}
	return metric
}

func newLowerBetterTrend(metric string, previous, current, samples int) MetricTrend {
	result := MetricTrend{Metric: metric, Previous: previous, Current: current, SampleCount: samples}
	switch {
	case current < previous:
		result.Trend = TrendImproving
	case current > previous:
		result.Trend = TrendDegrading
	default:
		result.Trend = TrendStable
	}
	return result
}

func overallTrend(trends []MetricTrend) Trend {
	for _, trend := range trends {
		if trend.Trend == TrendDegrading {
			return TrendDegrading
		}
	}
	for _, trend := range trends {
		if trend.Trend == TrendImproving {
			return TrendImproving
		}
	}
	for _, trend := range trends {
		if trend.Trend == TrendStable {
			return TrendStable
		}
	}
	return TrendInsufficientData
}

func deriveAnomalies(trends []MetricTrend) []Anomaly {
	values := make([]Anomaly, 0)
	for _, trend := range trends {
		if trend.Metric == "surface_coverage" || trend.Previous == 0 || trend.Current <= trend.Previous*2 {
			continue
		}
		values = append(values, Anomaly{Metric: trend.Metric, Observed: trend.Current, Reference: trend.Previous, Threshold: trend.Previous * 2, Reason: "recent_window_exceeds_twice_prior_window"})
	}
	sort.Slice(values, func(left, right int) bool { return values[left].Metric < values[right].Metric })
	return values
}

func deriveHealth(summary Summary, currentUnresolved int, historicalRecordsAvailable bool) AssessmentHealth {
	if !historicalRecordsAvailable {
		return AssessmentHealth{Index: 0, Classification: HealthUnknown, Dimensions: []string{}, Limitations: []string{"no_verified_assessment_history"}}
	}
	health := AssessmentHealth{Index: 100, Dimensions: []string{}, Limitations: []string{}}
	if summary.PolicyFailureCount > 0 {
		health.Index -= 20
		health.Dimensions = append(health.Dimensions, "policy_failures_present")
	}
	if summary.RegressionCount > 0 {
		health.Index -= 20
		health.Dimensions = append(health.Dimensions, "regressions_present")
	}
	if summary.Evidence.Stale+summary.Evidence.Contradictory > 0 {
		health.Index -= 15
		health.Dimensions = append(health.Dimensions, "evidence_freshness_or_consistency_degraded")
	}
	if currentUnresolved > 0 {
		deduction := currentUnresolved * 5
		if deduction > 20 {
			deduction = 20
		}
		health.Index -= deduction
		health.Dimensions = append(health.Dimensions, "governance_backlog_present")
	}
	if health.Index < 0 {
		health.Index = 0
	}
	sort.Strings(health.Dimensions)
	switch {
	case health.Index >= 80:
		health.Classification = HealthHealthy
	case health.Index >= 40:
		health.Classification = HealthDegraded
	default:
		health.Classification = HealthFailed
	}
	return health
}

func deriveDataQuality(records []HistoricalRecord, excludedCount int, exclusionReasons, limitations []string) DataQuality {
	quality := DataQuality{SourceCount: len(records) + excludedCount, ValidRecordCount: len(records), ExcludedRecordCount: excludedCount, ExclusionReasons: normalizeStrings(exclusionReasons), Limitations: []string{}}
	if containsString(limitations, "source_contradiction") {
		quality.Status = DataQualityContradictory
	} else if len(records) < 2 {
		quality.Status = DataQualityInsufficient
	} else if excludedCount > 0 || len(limitations) > 0 {
		quality.Status = DataQualityPartial
	} else {
		quality.Status = DataQualityComplete
	}
	return quality
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func addEvidence(left, right EvidenceCounts) EvidenceCounts {
	return EvidenceCounts{Fresh: left.Fresh + right.Fresh, Stale: left.Stale + right.Stale, Contradictory: left.Contradictory + right.Contradictory, Incomplete: left.Incomplete + right.Incomplete, Unsupported: left.Unsupported + right.Unsupported, Reproducible: left.Reproducible + right.Reproducible}
}

func addGovernance(left, right GovernanceCounts) GovernanceCounts {
	return GovernanceCounts{Recommended: left.Recommended + right.Recommended, Acknowledged: left.Acknowledged + right.Acknowledged, Accepted: left.Accepted + right.Accepted, Deferred: left.Deferred + right.Deferred, Rejected: left.Rejected + right.Rejected, Completed: left.Completed + right.Completed, Expired: left.Expired + right.Expired, Unresolved: left.Unresolved + right.Unresolved}
}

func sumRecords(records []HistoricalRecord, value func(HistoricalRecord) int) int {
	total := 0
	for _, record := range records {
		total += value(record)
	}
	return total
}

func sourceFingerprints(records []HistoricalRecord) []string {
	result := make([]string, len(records))
	for index, record := range records {
		result[index] = record.SourceFingerprint
	}
	sort.Strings(result)
	return result
}

func collectLimitations(records []HistoricalRecord) []string {
	values := make([]string, 0)
	for _, record := range records {
		values = append(values, record.Limitations...)
	}
	return normalizeStrings(values)
}

func normalizeWindow(value Window) Window { return Window{From: value.From.UTC(), To: value.To.UTC()} }

func normalizeStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedUniqueStrings(values []string) bool {
	for index, value := range values {
		if !validIdentifier(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func sortedUniqueFingerprints(values []string) bool {
	for index, value := range values {
		if !validFingerprint(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func uniqueSources(records []HistoricalRecord) bool {
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if seen[record.SourceFingerprint] {
			return false
		}
		seen[record.SourceFingerprint] = true
	}
	return true
}

func validOptionalFingerprint(value string) bool { return value == "" || validFingerprint(value) }

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\t\x00") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "cookie", "authorization", "api_key", "apikey", "token", "secret", "bearer", "session="} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func snapshotFingerprint(snapshot AnalyticsSnapshot) string {
	encoded, _ := json.Marshal(struct {
		SchemaVersion      string
		ProjectID          string
		GeneratedAt        time.Time
		Window             Window
		SourceFingerprints []string
		Summary            Summary
		Trends             []MetricTrend
		OverallTrend       Trend
		Anomalies          []Anomaly
		Health             AssessmentHealth
		DataQuality        DataQuality
		Limitations        []string
	}{snapshot.SchemaVersion, snapshot.ProjectID, snapshot.GeneratedAt.UTC(), snapshot.Window, snapshot.SourceFingerprints, snapshot.Summary, snapshot.Trends, snapshot.OverallTrend, snapshot.Anomalies, snapshot.Health, snapshot.DataQuality, snapshot.Limitations})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
