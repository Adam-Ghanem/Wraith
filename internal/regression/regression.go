package regression

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

const SchemaVersion = "r18.v1"
const PolicyVersion = "r18-v1"

type Category string

const (
	CategorySurface  Category = "surface"
	CategoryFinding  Category = "finding"
	CategoryRisk     Category = "risk"
	CategoryEvidence Category = "evidence"
	CategoryCoverage Category = "coverage"
)

type ChangeType string

const (
	ChangeNewEndpoint            ChangeType = "new_endpoint"
	ChangeRemovedEndpoint        ChangeType = "removed_endpoint"
	ChangeNewParameter           ChangeType = "new_parameter"
	ChangeRemovedParameter       ChangeType = "removed_parameter"
	ChangeNewFinding             ChangeType = "new_finding"
	ChangeResolvedFinding        ChangeType = "resolved_finding"
	ChangeRiskIncreased          ChangeType = "risk_increased"
	ChangeRiskDecreased          ChangeType = "risk_decreased"
	ChangeEvidenceStale          ChangeType = "evidence_stale"
	ChangeReproducibilityChanged ChangeType = "reproducibility_changed"
	ChangeEvidenceContradiction  ChangeType = "evidence_contradiction"
	ChangeCoverageDecreased      ChangeType = "coverage_decreased"
	ChangeCoverageIncreased      ChangeType = "coverage_increased"
)

type Impact string

const (
	ImpactInformational Impact = "informational"
	ImpactLow           Impact = "low"
	ImpactMedium        Impact = "medium"
	ImpactHigh          Impact = "high"
	ImpactCritical      Impact = "critical"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceStrong    Confidence = "strong"
	ConfidenceProbable  Confidence = "probable"
	ConfidenceUncertain Confidence = "uncertain"
)

type Finding struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	RiskBand    string `json:"risk_band"`
	Status      string `json:"status"`
}

type Evidence struct {
	FindingID       string   `json:"finding_id"`
	Verification    string   `json:"verification"`
	Freshness       string   `json:"freshness"`
	Reproducibility string   `json:"reproducibility"`
	Gaps            []string `json:"gaps"`
	Contradictions  []string `json:"contradictions"`
}

type Coverage struct {
	Definition  string `json:"definition"`
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
}

type SnapshotInput struct {
	ProjectID, CampaignID, ScopeVersion, AssessmentID, SurfaceSnapshotID, SchemaVersion string
	CreatedAt                                                                           time.Time
	EndpointIDs, ParameterIDs                                                           []string
	Findings                                                                            []Finding
	Evidence                                                                            []Evidence
	Coverage                                                                            Coverage
}

type Snapshot struct {
	ProjectID         string     `json:"project_id"`
	CampaignID        string     `json:"campaign_id,omitempty"`
	ScopeVersion      string     `json:"scope_version"`
	AssessmentID      string     `json:"assessment_id,omitempty"`
	SurfaceSnapshotID string     `json:"surface_snapshot_id,omitempty"`
	SchemaVersion     string     `json:"schema_version"`
	Fingerprint       string     `json:"fingerprint"`
	CreatedAt         time.Time  `json:"created_at"`
	EndpointIDs       []string   `json:"endpoint_ids"`
	ParameterIDs      []string   `json:"parameter_ids"`
	Findings          []Finding  `json:"findings"`
	Evidence          []Evidence `json:"evidence"`
	Coverage          Coverage   `json:"coverage"`
}

type Item struct {
	Category   Category   `json:"category"`
	Change     ChangeType `json:"change_type"`
	Subject    string     `json:"subject_fingerprint"`
	Impact     Impact     `json:"impact"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
}

type Comparison struct {
	ProjectID           string `json:"project_id"`
	BaselineFingerprint string `json:"baseline_fingerprint"`
	CurrentFingerprint  string `json:"current_fingerprint"`
	PolicyVersion       string `json:"policy_version"`
	Fingerprint         string `json:"fingerprint"`
	Items               []Item `json:"items"`
}

func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	if !validInput(input) || !validIDList(input.EndpointIDs) || !validIDList(input.ParameterIDs) || !validFindings(input.Findings) || !validEvidence(input.Evidence) {
		return Snapshot{}, errors.New("invalid regression snapshot")
	}
	snapshot := Snapshot{ProjectID: input.ProjectID, CampaignID: input.CampaignID, ScopeVersion: input.ScopeVersion, AssessmentID: input.AssessmentID, SurfaceSnapshotID: input.SurfaceSnapshotID, SchemaVersion: input.SchemaVersion, CreatedAt: input.CreatedAt.UTC(), EndpointIDs: normalizedIDs(input.EndpointIDs), ParameterIDs: normalizedIDs(input.ParameterIDs), Findings: normalizedFindings(input.Findings), Evidence: normalizedEvidence(input.Evidence), Coverage: input.Coverage}
	if !validSnapshotContent(snapshot) {
		return Snapshot{}, errors.New("invalid regression snapshot")
	}
	snapshot.Fingerprint = snapshotFingerprint(snapshot)
	return snapshot, nil
}

func Compare(baseline, current Snapshot) (Comparison, error) {
	if !validSnapshot(baseline) || !validSnapshot(current) || baseline.ProjectID != current.ProjectID {
		return Comparison{}, errors.New("invalid or cross-project regression comparison")
	}
	result := Comparison{ProjectID: baseline.ProjectID, BaselineFingerprint: baseline.Fingerprint, CurrentFingerprint: current.Fingerprint, PolicyVersion: PolicyVersion, Items: []Item{}}
	for _, id := range setDifference(current.EndpointIDs, baseline.EndpointIDs) {
		result.Items = append(result.Items, newItem(CategorySurface, ChangeNewEndpoint, id, ImpactInformational, ConfidenceConfirmed, "endpoint_added"))
	}
	for _, id := range setDifference(baseline.EndpointIDs, current.EndpointIDs) {
		result.Items = append(result.Items, newItem(CategorySurface, ChangeRemovedEndpoint, id, ImpactInformational, ConfidenceConfirmed, "endpoint_removed"))
	}
	for _, id := range setDifference(current.ParameterIDs, baseline.ParameterIDs) {
		result.Items = append(result.Items, newItem(CategorySurface, ChangeNewParameter, id, ImpactLow, ConfidenceConfirmed, "parameter_added"))
	}
	for _, id := range setDifference(baseline.ParameterIDs, current.ParameterIDs) {
		result.Items = append(result.Items, newItem(CategorySurface, ChangeRemovedParameter, id, ImpactInformational, ConfidenceConfirmed, "parameter_removed"))
	}
	baselineFindings, currentFindings := findingsByFingerprint(baseline.Findings), findingsByFingerprint(current.Findings)
	for fingerprint, currentFinding := range currentFindings {
		baselineFinding, exists := baselineFindings[fingerprint]
		if !exists {
			result.Items = append(result.Items, newItem(CategoryFinding, ChangeNewFinding, fingerprint, impactFromSeverity(currentFinding.Severity), ConfidenceConfirmed, "finding_added"))
			continue
		}
		if riskRank(currentFinding.RiskBand) > riskRank(baselineFinding.RiskBand) || severityRank(currentFinding.Severity) > severityRank(baselineFinding.Severity) {
			result.Items = append(result.Items, newItem(CategoryRisk, ChangeRiskIncreased, fingerprint, impactFromSeverity(currentFinding.Severity), ConfidenceConfirmed, "risk_band_increased"))
		} else if riskRank(currentFinding.RiskBand) < riskRank(baselineFinding.RiskBand) || severityRank(currentFinding.Severity) < severityRank(baselineFinding.Severity) {
			result.Items = append(result.Items, newItem(CategoryRisk, ChangeRiskDecreased, fingerprint, ImpactLow, ConfidenceConfirmed, "risk_band_decreased"))
		}
	}
	for fingerprint := range baselineFindings {
		if _, exists := currentFindings[fingerprint]; !exists {
			result.Items = append(result.Items, newItem(CategoryFinding, ChangeResolvedFinding, fingerprint, ImpactInformational, ConfidenceProbable, "finding_absent_from_current_snapshot"))
		}
	}
	appendEvidenceChanges(&result, baseline.Evidence, current.Evidence)
	if comparableCoverage(baseline.Coverage, current.Coverage) && coveragePercent(current.Coverage) < coveragePercent(baseline.Coverage) {
		result.Items = append(result.Items, newItem(CategoryCoverage, ChangeCoverageDecreased, current.Coverage.Definition, ImpactMedium, ConfidenceConfirmed, "coverage_decreased"))
	} else if comparableCoverage(baseline.Coverage, current.Coverage) && coveragePercent(current.Coverage) > coveragePercent(baseline.Coverage) {
		result.Items = append(result.Items, newItem(CategoryCoverage, ChangeCoverageIncreased, current.Coverage.Definition, ImpactInformational, ConfidenceConfirmed, "coverage_increased"))
	}
	sort.Slice(result.Items, func(i, j int) bool { return itemKey(result.Items[i]) < itemKey(result.Items[j]) })
	result.Fingerprint = comparisonFingerprint(result)
	return result, nil
}

func appendEvidenceChanges(result *Comparison, baseline, current []Evidence) {
	previous, latest := evidenceByFinding(baseline), evidenceByFinding(current)
	for findingID, value := range latest {
		prior, exists := previous[findingID]
		if !exists {
			continue
		}
		if value.Freshness == "stale" && prior.Freshness != "stale" {
			result.Items = append(result.Items, newItem(CategoryEvidence, ChangeEvidenceStale, findingID, ImpactHigh, ConfidenceConfirmed, "evidence_stale"))
		}
		if value.Reproducibility != prior.Reproducibility {
			result.Items = append(result.Items, newItem(CategoryEvidence, ChangeReproducibilityChanged, findingID, ImpactMedium, ConfidenceConfirmed, "reproducibility_changed"))
		}
		if len(value.Contradictions) > 0 && len(prior.Contradictions) == 0 {
			result.Items = append(result.Items, newItem(CategoryEvidence, ChangeEvidenceContradiction, findingID, ImpactHigh, ConfidenceConfirmed, "evidence_contradiction"))
		}
	}
}

func validInput(input SnapshotInput) bool {
	return validID(input.ProjectID) && validOptionalID(input.CampaignID) && validID(input.ScopeVersion) && validOptionalID(input.AssessmentID) && validOptionalID(input.SurfaceSnapshotID) && input.SchemaVersion == SchemaVersion && !input.CreatedAt.IsZero() && validCoverage(input.Coverage)
}

func validSnapshot(snapshot Snapshot) bool {
	return validSnapshotContent(snapshot) && len(snapshot.Fingerprint) == 64 && snapshot.Fingerprint == snapshotFingerprint(snapshot)
}

func validSnapshotContent(snapshot Snapshot) bool {
	return validInput(SnapshotInput{ProjectID: snapshot.ProjectID, CampaignID: snapshot.CampaignID, ScopeVersion: snapshot.ScopeVersion, AssessmentID: snapshot.AssessmentID, SurfaceSnapshotID: snapshot.SurfaceSnapshotID, SchemaVersion: snapshot.SchemaVersion, CreatedAt: snapshot.CreatedAt, Coverage: snapshot.Coverage}) && validIDList(snapshot.EndpointIDs) && validIDList(snapshot.ParameterIDs) && validFindings(snapshot.Findings) && validEvidence(snapshot.Evidence)
}

func validCoverage(value Coverage) bool {
	return validID(value.Definition) && value.Numerator >= 0 && value.Denominator >= 0 && value.Numerator <= value.Denominator
}
func validID(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 512 && !secretLike(value)
}
func validOptionalID(value string) bool { return strings.TrimSpace(value) == "" || validID(value) }
func secretLike(value string) bool {
	return dataclassification.IsSecretLike(value)
}

func normalizedIDs(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if validID(value) {
			seen[strings.TrimSpace(value)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func normalizedFindings(values []Finding) []Finding {
	out := append([]Finding{}, values...)
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}
func normalizedEvidence(values []Evidence) []Evidence {
	out := append([]Evidence{}, values...)
	for i := range out {
		out[i].Gaps = normalizedIDs(out[i].Gaps)
		out[i].Contradictions = normalizedIDs(out[i].Contradictions)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}
func validFindings(values []Finding) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if !validID(value.ID) || !validID(value.Fingerprint) || !validID(value.Severity) || !validID(value.RiskBand) || !validID(value.Status) || seen[value.Fingerprint] {
			return false
		}
		seen[value.Fingerprint] = true
	}
	return true
}
func validEvidence(values []Evidence) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if !validID(value.FindingID) || !validID(value.Verification) || !validID(value.Freshness) || !validID(value.Reproducibility) || seen[value.FindingID] {
			return false
		}
		if !validIDList(value.Gaps) || !validIDList(value.Contradictions) {
			return false
		}
		seen[value.FindingID] = true
	}
	return true
}

func validIDList(values []string) bool {
	for _, value := range values {
		if !validID(value) {
			return false
		}
	}
	return true
}

func snapshotFingerprint(snapshot Snapshot) string {
	encoded, _ := json.Marshal(struct {
		ProjectID, CampaignID, ScopeVersion, AssessmentID, SurfaceSnapshotID, SchemaVersion string
		CreatedAt                                                                           time.Time
		EndpointIDs, ParameterIDs                                                           []string
		Findings                                                                            []Finding
		Evidence                                                                            []Evidence
		Coverage                                                                            Coverage
	}{snapshot.ProjectID, snapshot.CampaignID, snapshot.ScopeVersion, snapshot.AssessmentID, snapshot.SurfaceSnapshotID, snapshot.SchemaVersion, snapshot.CreatedAt, snapshot.EndpointIDs, snapshot.ParameterIDs, snapshot.Findings, snapshot.Evidence, snapshot.Coverage})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func comparisonFingerprint(comparison Comparison) string {
	encoded, _ := json.Marshal(struct {
		ProjectID, BaselineFingerprint, CurrentFingerprint, PolicyVersion string
		Items                                                             []Item
	}{comparison.ProjectID, comparison.BaselineFingerprint, comparison.CurrentFingerprint, comparison.PolicyVersion, comparison.Items})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func findingsByFingerprint(values []Finding) map[string]Finding {
	out := make(map[string]Finding, len(values))
	for _, value := range values {
		out[value.Fingerprint] = value
	}
	return out
}
func evidenceByFinding(values []Evidence) map[string]Evidence {
	out := make(map[string]Evidence, len(values))
	for _, value := range values {
		out[value.FindingID] = value
	}
	return out
}
func setDifference(left, right []string) []string {
	seen := map[string]bool{}
	for _, value := range right {
		seen[value] = true
	}
	out := make([]string, 0)
	for _, value := range left {
		if !seen[value] {
			out = append(out, value)
		}
	}
	return out
}
func newItem(category Category, change ChangeType, subject string, impact Impact, confidence Confidence, reason string) Item {
	return Item{Category: category, Change: change, Subject: subject, Impact: impact, Confidence: confidence, Reason: reason}
}
func itemKey(item Item) string {
	return strings.Join([]string{string(item.Category), string(item.Impact), item.Subject, string(item.Change), item.Reason}, "\x00")
}
func coveragePercent(value Coverage) int {
	if value.Denominator == 0 {
		return -1
	}
	return value.Numerator * 100 / value.Denominator
}

func comparableCoverage(baseline, current Coverage) bool {
	return baseline.Definition == current.Definition && baseline.Denominator > 0 && current.Denominator > 0
}
func severityRank(value string) int { return rank(value) }
func riskRank(value string) int     { return rank(value) }
func rank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
func impactFromSeverity(value string) Impact {
	switch rank(value) {
	case 5:
		return ImpactCritical
	case 4:
		return ImpactHigh
	case 3:
		return ImpactMedium
	case 2:
		return ImpactLow
	default:
		return ImpactInformational
	}
}
