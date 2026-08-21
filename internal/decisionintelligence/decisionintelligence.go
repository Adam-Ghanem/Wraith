// Package decisionintelligence derives bounded, explainable recommendations
// from already validated R18–R21 intelligence. It performs no I/O and never
// executes, schedules, or mutates an upstream lifecycle owner.
package decisionintelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

const (
	SchemaVersion   = "r22.v1"
	DecisionVersion = "r22.priority.v1"
	MaxCandidates   = 64
	MaxFactors      = 16
	MaxConstraints  = 16
	MaxSourceRefs   = 16
	MaxStringBytes  = 512
	MaxLimitations  = 64
)

type Priority string

const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

type CandidateState string

const (
	CandidateAllowed  CandidateState = "allowed"
	CandidateDegraded CandidateState = "degraded"
	CandidateBlocked  CandidateState = "blocked"
	CandidateUnknown  CandidateState = "unknown"
)

type Action string

const (
	ActionInvestigateRegression Action = "investigate_regression"
	ActionVerifyEvidence        Action = "verify_evidence"
	ActionReviewGovernance      Action = "review_governance"
	ActionReviewPolicy          Action = "review_policy"
	ActionIncreaseCoverage      Action = "increase_coverage"
	ActionRefreshBaseline       Action = "refresh_baseline"
	ActionResolveDataQuality    Action = "resolve_data_quality"
)

type FactorType string

const (
	FactorActiveRegression  FactorType = "active_regression"
	FactorPolicyFailure     FactorType = "policy_failure"
	FactorGovernanceBacklog FactorType = "governance_backlog"
	FactorHealthDegraded    FactorType = "health_degraded"
	FactorEvidenceStale     FactorType = "evidence_stale"
	FactorDataQuality       FactorType = "data_quality_degraded"
)

type ConstraintType string

const (
	ConstraintNoValidEvidence      ConstraintType = "no_valid_evidence"
	ConstraintSourceStale          ConstraintType = "source_stale"
	ConstraintSourceContradictory  ConstraintType = "source_contradictory"
	ConstraintPolicyBlocked        ConstraintType = "policy_blocked"
	ConstraintGovernanceBlocked    ConstraintType = "governance_blocked"
	ConstraintInsufficientCoverage ConstraintType = "insufficient_coverage"
	ConstraintInvalidSource        ConstraintType = "invalid_source"
	ConstraintCrossProject         ConstraintType = "cross_project_reference"
	ConstraintFingerprintMismatch  ConstraintType = "fingerprint_mismatch"
	ConstraintDataQualityFailure   ConstraintType = "data_quality_failure"
	ConstraintInsufficientData     ConstraintType = "insufficient_data"
)

type Confidence string

const (
	ConfidenceHigh    Confidence = "high"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceLow     Confidence = "low"
	ConfidenceUnknown Confidence = "unknown"
)

type Quality string

const (
	QualityComplete      Quality = "complete"
	QualityPartial       Quality = "partial"
	QualityInsufficient  Quality = "insufficient"
	QualityContradictory Quality = "contradictory"
)

// DecisionAction, DecisionConfidence, and DecisionQuality are explicit domain
// names for serialized R22 contracts. They retain the evaluator's compact enum
// representation without introducing parallel action, confidence, or quality
// models.
type DecisionAction = Action
type DecisionConfidence = Confidence
type DecisionQuality = Quality

// DecisionComparison carries only safe R18 comparison lineage. It describes
// recorded source identity and never recalculates or reinterprets R18 changes.
type DecisionComparison struct {
	BaselineFingerprint   string `json:"baseline_fingerprint"`
	CurrentFingerprint    string `json:"current_fingerprint"`
	ComparisonFingerprint string `json:"comparison_fingerprint"`
}

type RegressionSignal struct {
	Fingerprint string `json:"fingerprint"`
	ChangeType  string `json:"change_type"`
	Impact      string `json:"impact"`
	Confidence  string `json:"confidence"`
}

type PolicyState struct {
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	FailedRules int    `json:"failed_rules"`
}

type GovernanceState struct {
	Fingerprint string `json:"fingerprint"`
	Overall     string `json:"overall"`
	Unresolved  int    `json:"unresolved"`
}

type DecisionLineage struct {
	ProjectID             string `json:"project_id"`
	AnalyticsFingerprint  string `json:"analytics_fingerprint"`
	ComparisonFingerprint string `json:"comparison_fingerprint"`
	EvaluationFingerprint string `json:"evaluation_fingerprint"`
	PolicyFingerprint     string `json:"policy_fingerprint"`
	GovernanceFingerprint string `json:"governance_fingerprint"`
}

type Input struct {
	ProjectID         string                      `json:"project_id"`
	GeneratedAt       time.Time                   `json:"generated_at"`
	Analytics         analytics.AnalyticsSnapshot `json:"analytics"`
	Lineage           DecisionLineage             `json:"lineage"`
	Policy            PolicyState                 `json:"policy"`
	Governance        GovernanceState             `json:"governance"`
	RegressionSignals []RegressionSignal          `json:"regression_signals"`
}

type DecisionFactor struct {
	Type              FactorType `json:"type"`
	Weight            int        `json:"weight"`
	SourceFingerprint string     `json:"source_fingerprint"`
	Explanation       string     `json:"explanation"`
	Confidence        Confidence `json:"confidence"`
	Quality           Quality    `json:"quality"`
}

type DecisionConstraint struct {
	Type   ConstraintType `json:"type"`
	Reason string         `json:"reason"`
}

// DecisionRecommendation is metadata only. The pure evaluator and every
// downstream adapter must preserve NonExecuting=true; no recommendation can
// dispatch work, alter lifecycle state, or imply that an action occurred.
type DecisionRecommendation struct {
	Type         Action `json:"type"`
	NonExecuting bool   `json:"non_executing"`
}

type DecisionReason struct {
	Code              string `json:"code"`
	Explanation       string `json:"explanation"`
	SourceFingerprint string `json:"source_fingerprint"`
}

type DecisionCandidate struct {
	ID             string                 `json:"id"`
	Priority       Priority               `json:"priority"`
	State          CandidateState         `json:"state"`
	Action         Action                 `json:"recommended_action"`
	Recommendation DecisionRecommendation `json:"recommendation"`
	Reasons        []DecisionReason       `json:"reasons"`
	Score          int                    `json:"score"`
	Confidence     Confidence             `json:"confidence"`
	Quality        Quality                `json:"quality"`
	Factors        []DecisionFactor       `json:"factors"`
	Constraints    []DecisionConstraint   `json:"constraints"`
	Lineage        DecisionLineage        `json:"lineage"`
	Fingerprint    string                 `json:"fingerprint"`
}

type DecisionSnapshot struct {
	SchemaVersion      string              `json:"schema_version"`
	DecisionVersion    string              `json:"decision_version"`
	ProjectID          string              `json:"project"`
	GeneratedAt        time.Time           `json:"generated_at"`
	SourceFingerprints []string            `json:"source_fingerprints"`
	DataQuality        Quality             `json:"data_quality"`
	Limitations        []string            `json:"limitations"`
	Candidates         []DecisionCandidate `json:"candidates"`
	Fingerprint        string              `json:"fingerprint"`
}

func Evaluate(input Input) (DecisionSnapshot, error) {
	if strings.TrimSpace(input.ProjectID) != "" && strings.TrimSpace(input.Lineage.ProjectID) != "" && strings.TrimSpace(input.ProjectID) != strings.TrimSpace(input.Lineage.ProjectID) {
		return DecisionSnapshot{}, errors.New("cross-project decision source lineage")
	}
	if !validInput(input) {
		return DecisionSnapshot{}, errors.New("invalid decision intelligence input")
	}
	quality := qualityFromAnalytics(input.Analytics.DataQuality.Status)
	constraints := baseConstraints(input, quality)
	regressions := append([]RegressionSignal{}, input.RegressionSignals...)
	sort.Slice(regressions, func(left, right int) bool {
		return regressionKey(regressions[left]) < regressionKey(regressions[right])
	})
	candidates := make([]DecisionCandidate, 0, min(len(regressions)+3, MaxCandidates))
	for _, signal := range regressions {
		candidate := newRegressionCandidate(input, quality, constraints, signal)
		candidates = append(candidates, candidate)
	}
	if input.Policy.FailedRules > 0 && len(candidates) < MaxCandidates {
		candidates = append(candidates, newPolicyCandidate(input, quality, constraints))
	}
	if input.Governance.Unresolved > 0 && len(candidates) < MaxCandidates {
		candidates = append(candidates, newGovernanceCandidate(input, quality, constraints))
	}
	if input.Analytics.Summary.Evidence.Stale+input.Analytics.Summary.Evidence.Contradictory > 0 && len(candidates) < MaxCandidates {
		candidates = append(candidates, newEvidenceCandidate(input, quality, constraints))
	}
	if len(candidates) == 0 && quality != QualityComplete {
		candidates = append(candidates, newQualityCandidate(input, quality, constraints))
	}
	for index := range candidates {
		candidates[index].Fingerprint = candidateFingerprint(candidates[index])
		candidates[index].ID = candidates[index].Fingerprint
	}
	sort.Slice(candidates, func(left, right int) bool { return candidateKey(candidates[left]) < candidateKey(candidates[right]) })
	result := DecisionSnapshot{
		SchemaVersion:      SchemaVersion,
		DecisionVersion:    DecisionVersion,
		ProjectID:          strings.TrimSpace(input.ProjectID),
		GeneratedAt:        input.GeneratedAt.UTC(),
		SourceFingerprints: sourceFingerprints(input.Lineage),
		DataQuality:        quality,
		Limitations:        limitations(input.Analytics, quality),
		Candidates:         candidates,
	}
	result.Fingerprint = snapshotFingerprint(result)
	return result, nil
}

func ValidateSnapshot(snapshot DecisionSnapshot) bool {
	if snapshot.SchemaVersion != SchemaVersion || snapshot.DecisionVersion != DecisionVersion || !validIdentifier(snapshot.ProjectID) || snapshot.GeneratedAt.IsZero() || !validQuality(snapshot.DataQuality) || !validFingerprint(snapshot.Fingerprint) || !sortedUniqueFingerprints(snapshot.SourceFingerprints) || !sortedUniqueIdentifiers(snapshot.Limitations) || len(snapshot.Candidates) > MaxCandidates {
		return false
	}
	for index, candidate := range snapshot.Candidates {
		if !validCandidate(candidate, snapshot.ProjectID) || (index > 0 && candidateKey(snapshot.Candidates[index-1]) >= candidateKey(candidate)) {
			return false
		}
	}
	return snapshot.Fingerprint == snapshotFingerprint(snapshot)
}

func newRegressionCandidate(input Input, quality Quality, constraints []DecisionConstraint, signal RegressionSignal) DecisionCandidate {
	factors := []DecisionFactor{regressionFactor(signal, quality)}
	if input.Policy.FailedRules > 0 {
		factors = append(factors, policyFactor(input.Policy, quality))
	}
	return completeCandidate(input, quality, constraints, actionForSignal(signal), factors)
}

func newPolicyCandidate(input Input, quality Quality, constraints []DecisionConstraint) DecisionCandidate {
	return completeCandidate(input, quality, constraints, ActionReviewPolicy, []DecisionFactor{policyFactor(input.Policy, quality)})
}

func newGovernanceCandidate(input Input, quality Quality, constraints []DecisionConstraint) DecisionCandidate {
	weight := input.Governance.Unresolved * 5
	if weight > 20 {
		weight = 20
	}
	factor := DecisionFactor{Type: FactorGovernanceBacklog, Weight: weight, SourceFingerprint: input.Governance.Fingerprint, Explanation: "validated_unresolved_governance_backlog", Confidence: confidenceFor(quality), Quality: quality}
	return completeCandidate(input, quality, constraints, ActionReviewGovernance, []DecisionFactor{factor})
}

func newEvidenceCandidate(input Input, quality Quality, constraints []DecisionConstraint) DecisionCandidate {
	factor := DecisionFactor{Type: FactorEvidenceStale, Weight: 35, SourceFingerprint: input.Analytics.Fingerprint, Explanation: "validated_r18_evidence_freshness_requires_verification", Confidence: confidenceFor(quality), Quality: quality}
	return completeCandidate(input, quality, constraints, ActionVerifyEvidence, []DecisionFactor{factor})
}

func newQualityCandidate(input Input, quality Quality, constraints []DecisionConstraint) DecisionCandidate {
	factor := DecisionFactor{Type: FactorDataQuality, Weight: 0, SourceFingerprint: input.Analytics.Fingerprint, Explanation: "validated_analytics_data_quality_requires_review", Confidence: confidenceFor(quality), Quality: quality}
	return completeCandidate(input, quality, constraints, ActionResolveDataQuality, []DecisionFactor{factor})
}

func completeCandidate(input Input, quality Quality, constraints []DecisionConstraint, action Action, factors []DecisionFactor) DecisionCandidate {
	factors = append([]DecisionFactor{}, factors...)
	sort.Slice(factors, func(left, right int) bool { return factorKey(factors[left]) < factorKey(factors[right]) })
	normalizedConstraints := append([]DecisionConstraint{}, constraints...)
	sort.Slice(normalizedConstraints, func(left, right int) bool {
		return constraintKey(normalizedConstraints[left]) < constraintKey(normalizedConstraints[right])
	})
	score := 0
	for _, factor := range factors {
		score += factor.Weight
	}
	if score > 100 {
		score = 100
	}
	state := CandidateAllowed
	if len(normalizedConstraints) > 0 {
		state = CandidateBlocked
	} else if quality == QualityPartial {
		state = CandidateDegraded
	} else if quality == QualityInsufficient {
		state = CandidateUnknown
	}
	return DecisionCandidate{Priority: priorityFor(score), State: state, Action: action, Recommendation: DecisionRecommendation{Type: action, NonExecuting: true}, Reasons: reasonsFor(factors), Score: score, Confidence: confidenceFor(quality), Quality: quality, Factors: factors, Constraints: normalizedConstraints, Lineage: input.Lineage}
}

func regressionFactor(signal RegressionSignal, quality Quality) DecisionFactor {
	return DecisionFactor{Type: FactorActiveRegression, Weight: impactWeight(signal.Impact), SourceFingerprint: signal.Fingerprint, Explanation: "validated_r18_regression_requires_review", Confidence: confidenceFromSignal(signal.Confidence, quality), Quality: quality}
}

func policyFactor(policy PolicyState, quality Quality) DecisionFactor {
	return DecisionFactor{Type: FactorPolicyFailure, Weight: 20, SourceFingerprint: policy.Fingerprint, Explanation: "validated_r19_policy_failure_requires_review", Confidence: confidenceFor(quality), Quality: quality}
}

func baseConstraints(input Input, quality Quality) []DecisionConstraint {
	values := []DecisionConstraint{}
	switch quality {
	case QualityContradictory:
		values = append(values, DecisionConstraint{Type: ConstraintDataQualityFailure, Reason: "validated_r21_data_quality_is_contradictory"})
	case QualityInsufficient:
		values = append(values, DecisionConstraint{Type: ConstraintInsufficientData, Reason: "validated_r21_data_quality_is_insufficient"})
	}
	if input.Governance.Overall == "stale" {
		values = append(values, DecisionConstraint{Type: ConstraintSourceStale, Reason: "validated_r20_governance_state_is_stale"})
	}
	if input.Governance.Overall == "unknown" {
		values = append(values, DecisionConstraint{Type: ConstraintGovernanceBlocked, Reason: "validated_r20_governance_state_is_unknown"})
	}
	return values
}

func actionForSignal(signal RegressionSignal) Action {
	switch signal.ChangeType {
	case "evidence_stale", "evidence_contradiction", "reproducibility_changed":
		return ActionVerifyEvidence
	case "coverage_decreased":
		return ActionIncreaseCoverage
	default:
		return ActionInvestigateRegression
	}
}

func priorityFor(score int) Priority {
	switch {
	case score >= 70:
		return PriorityP0
	case score >= 50:
		return PriorityP1
	case score >= 30:
		return PriorityP2
	case score >= 15:
		return PriorityP3
	default:
		return PriorityP4
	}
}

func impactWeight(impact string) int {
	switch impact {
	case "critical":
		return 60
	case "high":
		return 45
	case "medium":
		return 30
	case "low":
		return 15
	default:
		return 5
	}
}

func qualityFromAnalytics(value analytics.DataQualityStatus) Quality {
	switch value {
	case analytics.DataQualityComplete:
		return QualityComplete
	case analytics.DataQualityPartial:
		return QualityPartial
	case analytics.DataQualityInsufficient:
		return QualityInsufficient
	default:
		return QualityContradictory
	}
}

func confidenceFor(quality Quality) Confidence {
	switch quality {
	case QualityComplete:
		return ConfidenceHigh
	case QualityPartial:
		return ConfidenceMedium
	case QualityInsufficient:
		return ConfidenceLow
	default:
		return ConfidenceUnknown
	}
}

func confidenceFromSignal(value string, quality Quality) Confidence {
	if quality != QualityComplete {
		return confidenceFor(quality)
	}
	switch value {
	case "confirmed", "strong":
		return ConfidenceHigh
	case "probable":
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func limitations(snapshot analytics.AnalyticsSnapshot, quality Quality) []string {
	values := append([]string{}, snapshot.Limitations...)
	if quality != QualityComplete {
		values = append(values, "decision_source_quality_"+string(quality))
	}
	return normalizeIdentifiers(values)
}

func sourceFingerprints(lineage DecisionLineage) []string {
	return sortedFingerprints([]string{lineage.AnalyticsFingerprint, lineage.ComparisonFingerprint, lineage.EvaluationFingerprint, lineage.PolicyFingerprint, lineage.GovernanceFingerprint})
}

func validInput(input Input) bool {
	if !validIdentifier(input.ProjectID) || input.GeneratedAt.IsZero() || !analytics.ValidateSnapshot(input.Analytics) || input.Analytics.ProjectID != strings.TrimSpace(input.ProjectID) || !validLineage(input.Lineage, input.ProjectID) || input.Lineage.AnalyticsFingerprint != input.Analytics.Fingerprint || !validPolicy(input.Policy, input.Lineage.PolicyFingerprint) || !validGovernance(input.Governance, input.Lineage.GovernanceFingerprint) || len(input.RegressionSignals) > MaxCandidates {
		return false
	}
	seen := map[string]bool{}
	for _, signal := range input.RegressionSignals {
		if !validSignal(signal) || seen[signal.Fingerprint] {
			return false
		}
		seen[signal.Fingerprint] = true
	}
	return true
}

func validLineage(value DecisionLineage, projectID string) bool {
	return value.ProjectID == strings.TrimSpace(projectID) && validIdentifier(value.ProjectID) && validFingerprint(value.AnalyticsFingerprint) && validFingerprint(value.ComparisonFingerprint) && validFingerprint(value.EvaluationFingerprint) && validFingerprint(value.PolicyFingerprint) && validFingerprint(value.GovernanceFingerprint)
}

func validPolicy(value PolicyState, expectedFingerprint string) bool {
	return value.Fingerprint == expectedFingerprint && validFingerprint(value.Fingerprint) && (value.Status == "pass" || value.Status == "failed" || value.Status == "unknown") && value.FailedRules >= 0 && value.FailedRules <= MaxFactors
}

func validGovernance(value GovernanceState, expectedFingerprint string) bool {
	return value.Fingerprint == expectedFingerprint && validFingerprint(value.Fingerprint) && (value.Overall == "healthy" || value.Overall == "degraded" || value.Overall == "failed" || value.Overall == "stale" || value.Overall == "unknown") && value.Unresolved >= 0 && value.Unresolved <= MaxCandidates
}

func validSignal(value RegressionSignal) bool {
	return validFingerprint(value.Fingerprint) && validIdentifier(value.ChangeType) && validImpact(value.Impact) && validSignalConfidence(value.Confidence)
}

func validCandidate(value DecisionCandidate, projectID string) bool {
	if value.ID != value.Fingerprint || !validFingerprint(value.ID) || !validPriority(value.Priority) || !validCandidateState(value.State) || !validAction(value.Action) || !validRecommendation(value.Recommendation, value.Action) || value.Score < 0 || value.Score > 100 || !validConfidence(value.Confidence) || !validQuality(value.Quality) || len(value.Factors) == 0 || len(value.Factors) > MaxFactors || len(value.Constraints) > MaxConstraints || !validLineage(value.Lineage, projectID) || !validFingerprint(value.Fingerprint) {
		return false
	}
	for index, factor := range value.Factors {
		if !validFactor(factor) || (index > 0 && factorKey(value.Factors[index-1]) >= factorKey(factor)) {
			return false
		}
	}
	for index, constraint := range value.Constraints {
		if !validConstraint(constraint) || (index > 0 && constraintKey(value.Constraints[index-1]) >= constraintKey(constraint)) {
			return false
		}
	}
	for index, reason := range value.Reasons {
		if !validReason(reason) || (index > 0 && reasonKey(value.Reasons[index-1]) >= reasonKey(reason)) {
			return false
		}
	}
	return value.Fingerprint == candidateFingerprint(value)
}

func validFactor(value DecisionFactor) bool {
	return validFactorType(value.Type) && value.Weight >= 0 && value.Weight <= 100 && validFingerprint(value.SourceFingerprint) && validIdentifier(value.Explanation) && validConfidence(value.Confidence) && validQuality(value.Quality)
}

func validConstraint(value DecisionConstraint) bool {
	return validConstraintType(value.Type) && validIdentifier(value.Reason)
}
func validRecommendation(value DecisionRecommendation, action Action) bool {
	return value.Type == action && validAction(value.Type) && value.NonExecuting
}
func validReason(value DecisionReason) bool {
	return validIdentifier(value.Code) && validIdentifier(value.Explanation) && validFingerprint(value.SourceFingerprint)
}

func validPriority(value Priority) bool {
	return value == PriorityP0 || value == PriorityP1 || value == PriorityP2 || value == PriorityP3 || value == PriorityP4
}
func validCandidateState(value CandidateState) bool {
	return value == CandidateAllowed || value == CandidateDegraded || value == CandidateBlocked || value == CandidateUnknown
}
func validAction(value Action) bool {
	return value == ActionInvestigateRegression || value == ActionVerifyEvidence || value == ActionReviewGovernance || value == ActionReviewPolicy || value == ActionIncreaseCoverage || value == ActionRefreshBaseline || value == ActionResolveDataQuality
}
func validFactorType(value FactorType) bool {
	return value == FactorActiveRegression || value == FactorPolicyFailure || value == FactorGovernanceBacklog || value == FactorHealthDegraded || value == FactorEvidenceStale || value == FactorDataQuality
}
func validConstraintType(value ConstraintType) bool {
	switch value {
	case ConstraintNoValidEvidence, ConstraintSourceStale, ConstraintSourceContradictory, ConstraintPolicyBlocked, ConstraintGovernanceBlocked, ConstraintInsufficientCoverage, ConstraintInvalidSource, ConstraintCrossProject, ConstraintFingerprintMismatch, ConstraintDataQualityFailure, ConstraintInsufficientData:
		return true
	}
	return false
}
func validConfidence(value Confidence) bool {
	return value == ConfidenceHigh || value == ConfidenceMedium || value == ConfidenceLow || value == ConfidenceUnknown
}
func validQuality(value Quality) bool {
	return value == QualityComplete || value == QualityPartial || value == QualityInsufficient || value == QualityContradictory
}
func validImpact(value string) bool {
	return value == "critical" || value == "high" || value == "medium" || value == "low" || value == "informational"
}
func validSignalConfidence(value string) bool {
	return value == "confirmed" || value == "strong" || value == "probable" || value == "uncertain"
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxStringBytes && !strings.ContainsAny(value, "\r\n\t\x00") && !secretLike(value)
}

func validFingerprint(value string) bool {
	if len(value) != 64 || secretLike(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func secretLike(value string) bool {
	return dataclassification.IsSecretLike(value)
}

func normalizeIdentifiers(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if validIdentifier(value) {
			seen[strings.TrimSpace(value)] = true
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	if len(result) > MaxLimitations {
		return result[:MaxLimitations]
	}
	return result
}

func sortedFingerprints(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func sortedUniqueFingerprints(values []string) bool {
	for index, value := range values {
		if !validFingerprint(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return len(values) > 0 && len(values) <= MaxSourceRefs
}
func sortedUniqueIdentifiers(values []string) bool {
	for index, value := range values {
		if !validIdentifier(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return len(values) <= MaxLimitations
}

func regressionKey(value RegressionSignal) string {
	return value.Fingerprint + "\x00" + value.ChangeType + "\x00" + value.Impact
}
func factorKey(value DecisionFactor) string {
	return string(value.Type) + "\x00" + value.SourceFingerprint + "\x00" + value.Explanation
}
func constraintKey(value DecisionConstraint) string {
	return string(value.Type) + "\x00" + value.Reason
}
func reasonKey(value DecisionReason) string {
	return value.Code + "\x00" + value.SourceFingerprint + "\x00" + value.Explanation
}
func candidateKey(value DecisionCandidate) string {
	return priorityRank(value.Priority) + "\x00" + string(value.Action) + "\x00" + value.Fingerprint
}
func priorityRank(value Priority) string { return string(value) }

func candidateFingerprint(value DecisionCandidate) string {
	encoded, _ := json.Marshal(struct {
		Priority       Priority
		State          CandidateState
		Action         Action
		Recommendation DecisionRecommendation
		Reasons        []DecisionReason
		Score          int
		Confidence     Confidence
		Quality        Quality
		Factors        []DecisionFactor
		Constraints    []DecisionConstraint
		Lineage        DecisionLineage
	}{value.Priority, value.State, value.Action, value.Recommendation, value.Reasons, value.Score, value.Confidence, value.Quality, value.Factors, value.Constraints, value.Lineage})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func snapshotFingerprint(value DecisionSnapshot) string {
	encoded, _ := json.Marshal(struct {
		SchemaVersion, DecisionVersion, ProjectID string
		GeneratedAt                               time.Time
		SourceFingerprints                        []string
		DataQuality                               Quality
		Limitations                               []string
		Candidates                                []DecisionCandidate
	}{value.SchemaVersion, value.DecisionVersion, value.ProjectID, value.GeneratedAt.UTC(), value.SourceFingerprints, value.DataQuality, value.Limitations, value.Candidates})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func reasonsFor(factors []DecisionFactor) []DecisionReason {
	values := make([]DecisionReason, 0, len(factors))
	for _, factor := range factors {
		values = append(values, DecisionReason{Code: "factor_" + string(factor.Type), Explanation: factor.Explanation, SourceFingerprint: factor.SourceFingerprint})
	}
	sort.Slice(values, func(left, right int) bool { return reasonKey(values[left]) < reasonKey(values[right]) })
	return values
}
