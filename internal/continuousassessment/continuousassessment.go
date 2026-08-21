// Package continuousassessment evaluates explicit local policy against
// existing R18 snapshots and comparisons. It owns no network, lifecycle, or
// persistence behavior.
package continuousassessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

const (
	SchemaVersion  = "r19.v1"
	PolicyVersion  = 1
	MaxPolicyBytes = 64 << 10
	MaxRules       = 64
	MaxActions     = 128
	MaxStringBytes = 512
)

type RuleType string

const (
	RuleFindingCount           RuleType = "finding_count"
	RuleFindingSeverity        RuleType = "finding_severity"
	RuleNewFinding             RuleType = "new_finding"
	RuleResolvedFinding        RuleType = "resolved_finding"
	RuleReopenedFinding        RuleType = "reopened_finding"
	RuleRegression             RuleType = "regression"
	RuleAttackSurfaceGrowth    RuleType = "attack_surface_growth"
	RuleAttackSurfaceReduction RuleType = "attack_surface_reduction"
	RuleEvidenceFreshness      RuleType = "evidence_freshness"
	RuleEvidenceVerification   RuleType = "evidence_verification"
	RuleContradiction          RuleType = "contradiction"
	RuleCoverage               RuleType = "coverage"
	RuleReproducibility        RuleType = "reproducibility"
	RuleMissingLineage         RuleType = "missing_lineage"
	RuleRiskBand               RuleType = "risk_band"
	RuleRiskScoreDelta         RuleType = "risk_score_delta"
	RuleTaskFailure            RuleType = "task_failure"
	RuleAssessmentCompletion   RuleType = "assessment_completion"
)

type Operator string

const (
	OperatorMaximum Operator = "maximum"
	OperatorMinimum Operator = "minimum"
)

type Unit string

const (
	UnitCount       Unit = "count"
	UnitBasisPoints Unit = "basis_points"
)

type Effect string

const (
	EffectFail          Effect = "fail"
	EffectWarning       Effect = "warning"
	EffectInformational Effect = "informational"
)

type DecisionStatus string

const (
	StatusPass          DecisionStatus = "pass"
	StatusFail          DecisionStatus = "fail"
	StatusWarning       DecisionStatus = "warning"
	StatusInformational DecisionStatus = "informational"
	StatusSkipped       DecisionStatus = "skipped"
	StatusUnsupported   DecisionStatus = "unsupported"
	StatusUnknown       DecisionStatus = "unknown"
)

type ActionStatus string

const ActionRecommended ActionStatus = "recommended"

type Threshold struct {
	Value int  `json:"value"`
	Unit  Unit `json:"unit"`
}

type PolicyRule struct {
	ID        string    `json:"id"`
	Type      RuleType  `json:"type"`
	Operator  Operator  `json:"operator"`
	Threshold Threshold `json:"threshold"`
	Effect    Effect    `json:"effect"`
	Severity  string    `json:"severity,omitempty"`
	Scope     string    `json:"scope,omitempty"`
}

type PolicyInput struct {
	ProjectID string
	Name      string
	Version   int
	Rules     []PolicyRule
}

type AssessmentPolicy struct {
	ProjectID     string       `json:"project_id"`
	Name          string       `json:"name"`
	Version       int          `json:"version"`
	SchemaVersion string       `json:"schema_version"`
	Fingerprint   string       `json:"fingerprint"`
	Rules         []PolicyRule `json:"rules"`
}

type BaselineInput struct {
	ProjectID           string
	SnapshotFingerprint string
	SnapshotCreatedAt   time.Time
	PolicyFingerprint   string
	CampaignID          string
	Description         string
	CreatedAt           time.Time
}

type AssessmentBaseline struct {
	ProjectID           string    `json:"project_id"`
	SnapshotFingerprint string    `json:"snapshot_fingerprint"`
	SnapshotCreatedAt   time.Time `json:"snapshot_created_at"`
	PolicyFingerprint   string    `json:"policy_fingerprint"`
	CampaignID          string    `json:"campaign_id,omitempty"`
	Description         string    `json:"description,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	Fingerprint         string    `json:"fingerprint"`
}

type ControlDecision struct {
	RuleID                string         `json:"rule_id"`
	Status                DecisionStatus `json:"status"`
	ObservedValue         int            `json:"observed_value"`
	ExpectedValue         int            `json:"expected_value"`
	Unit                  Unit           `json:"unit"`
	Explanation           string         `json:"explanation"`
	BaselineFingerprint   string         `json:"baseline_fingerprint"`
	CurrentFingerprint    string         `json:"current_fingerprint"`
	ComparisonFingerprint string         `json:"comparison_fingerprint"`
	Fingerprint           string         `json:"fingerprint"`
}

type AssessmentAction struct {
	ID                        string       `json:"id"`
	ProjectID                 string       `json:"project_id"`
	RuleID                    string       `json:"rule_id"`
	Kind                      string       `json:"kind"`
	Priority                  string       `json:"priority"`
	Rationale                 string       `json:"rationale"`
	CampaignID                string       `json:"campaign_id,omitempty"`
	Status                    ActionStatus `json:"status"`
	SourceDecisionFingerprint string       `json:"source_decision_fingerprint"`
}

type AssessmentSummary struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Warnings      int `json:"warnings"`
	Informational int `json:"informational"`
	Skipped       int `json:"skipped"`
	Unsupported   int `json:"unsupported"`
	Unknown       int `json:"unknown"`
}

type ControlEvaluation struct {
	ProjectID             string             `json:"project_id"`
	PolicyFingerprint     string             `json:"policy_fingerprint"`
	BaselineFingerprint   string             `json:"baseline_fingerprint"`
	BaselineSnapshot      string             `json:"baseline_snapshot_fingerprint"`
	CurrentSnapshot       string             `json:"current_snapshot_fingerprint"`
	ComparisonFingerprint string             `json:"comparison_fingerprint"`
	EvaluatedAt           time.Time          `json:"evaluated_at"`
	Summary               AssessmentSummary  `json:"summary"`
	Decisions             []ControlDecision  `json:"decisions"`
	Actions               []AssessmentAction `json:"actions"`
	Fingerprint           string             `json:"fingerprint"`
}

type EvaluationInput struct {
	ProjectID        string
	Policy           AssessmentPolicy
	Baseline         AssessmentBaseline
	BaselineSnapshot regression.Snapshot
	CurrentSnapshot  regression.Snapshot
	Comparison       regression.Comparison
	EvaluatedAt      time.Time
}

func NewPolicy(input PolicyInput) (AssessmentPolicy, error) {
	policy := AssessmentPolicy{ProjectID: strings.TrimSpace(input.ProjectID), Name: strings.TrimSpace(input.Name), Version: input.Version, SchemaVersion: SchemaVersion, Rules: append([]PolicyRule{}, input.Rules...)}
	if !validPolicyContent(policy) {
		return AssessmentPolicy{}, errors.New("invalid continuous assessment policy")
	}
	sort.Slice(policy.Rules, func(left, right int) bool { return policy.Rules[left].ID < policy.Rules[right].ID })
	policy.Fingerprint = policyFingerprint(policy)
	return policy, nil
}

func ParsePolicy(document []byte) (AssessmentPolicy, error) {
	if len(document) == 0 || len(document) > MaxPolicyBytes {
		return AssessmentPolicy{}, errors.New("invalid continuous assessment policy document")
	}
	var input struct {
		ProjectID string       `json:"project_id"`
		Name      string       `json:"name"`
		Version   int          `json:"version"`
		Rules     []PolicyRule `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.More() {
		return AssessmentPolicy{}, errors.New("invalid continuous assessment policy document")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AssessmentPolicy{}, errors.New("invalid continuous assessment policy document")
	}
	return NewPolicy(PolicyInput{ProjectID: input.ProjectID, Name: input.Name, Version: input.Version, Rules: input.Rules})
}

func NewBaseline(input BaselineInput) (AssessmentBaseline, error) {
	baseline := AssessmentBaseline{ProjectID: strings.TrimSpace(input.ProjectID), SnapshotFingerprint: strings.TrimSpace(input.SnapshotFingerprint), SnapshotCreatedAt: input.SnapshotCreatedAt.UTC(), PolicyFingerprint: strings.TrimSpace(input.PolicyFingerprint), CampaignID: strings.TrimSpace(input.CampaignID), Description: strings.TrimSpace(input.Description), CreatedAt: input.CreatedAt.UTC()}
	if !validID(baseline.ProjectID) || !validFingerprint(baseline.SnapshotFingerprint) || !validFingerprint(baseline.PolicyFingerprint) || !validOptionalID(baseline.CampaignID) || !validOptionalID(baseline.Description) || baseline.SnapshotCreatedAt.IsZero() || baseline.CreatedAt.IsZero() {
		return AssessmentBaseline{}, errors.New("invalid continuous assessment baseline")
	}
	baseline.Fingerprint = baselineFingerprint(baseline)
	return baseline, nil
}

func Evaluate(input EvaluationInput) (ControlEvaluation, error) {
	if !validEvaluationInput(input) {
		return ControlEvaluation{}, errors.New("invalid continuous assessment evaluation")
	}
	evaluation := ControlEvaluation{ProjectID: input.ProjectID, PolicyFingerprint: input.Policy.Fingerprint, BaselineFingerprint: input.Baseline.Fingerprint, BaselineSnapshot: input.BaselineSnapshot.Fingerprint, CurrentSnapshot: input.CurrentSnapshot.Fingerprint, ComparisonFingerprint: input.Comparison.Fingerprint, EvaluatedAt: input.EvaluatedAt.UTC(), Decisions: make([]ControlDecision, 0, len(input.Policy.Rules)), Actions: []AssessmentAction{}}
	for _, rule := range input.Policy.Rules {
		decision := evaluateRule(rule, input, evaluation)
		decision.Fingerprint = fingerprint(struct {
			RuleID, Explanation, BaselineFingerprint, CurrentFingerprint, ComparisonFingerprint string
			Status                                                                              DecisionStatus
			ObservedValue, ExpectedValue                                                        int
			Unit                                                                                Unit
		}{decision.RuleID, decision.Explanation, decision.BaselineFingerprint, decision.CurrentFingerprint, decision.ComparisonFingerprint, decision.Status, decision.ObservedValue, decision.ExpectedValue, decision.Unit})
		evaluation.Decisions = append(evaluation.Decisions, decision)
		applySummary(&evaluation.Summary, decision.Status)
		if (decision.Status == StatusFail || decision.Status == StatusWarning) && len(evaluation.Actions) < MaxActions {
			evaluation.Actions = append(evaluation.Actions, actionFor(rule, decision, input.Baseline.CampaignID, input.ProjectID))
		}
	}
	evaluation.Fingerprint = fingerprint(struct {
		ProjectID, PolicyFingerprint, BaselineFingerprint, BaselineSnapshot, CurrentSnapshot, ComparisonFingerprint string
		EvaluatedAt                                                                                                 time.Time
		Decisions                                                                                                   []ControlDecision
		Actions                                                                                                     []AssessmentAction
	}{evaluation.ProjectID, evaluation.PolicyFingerprint, evaluation.BaselineFingerprint, evaluation.BaselineSnapshot, evaluation.CurrentSnapshot, evaluation.ComparisonFingerprint, evaluation.EvaluatedAt, evaluation.Decisions, evaluation.Actions})
	return evaluation, nil
}

func validPolicy(policy AssessmentPolicy) bool {
	return validPolicyContent(policy) && validFingerprint(policy.Fingerprint) && policy.Fingerprint == policyFingerprint(policy)
}

func validPolicyContent(policy AssessmentPolicy) bool {
	if !validID(policy.ProjectID) || !validID(policy.Name) || policy.Version != PolicyVersion || policy.SchemaVersion != SchemaVersion || len(policy.Rules) == 0 || len(policy.Rules) > MaxRules {
		return false
	}
	seen := map[string]bool{}
	for _, rule := range policy.Rules {
		if !validRule(rule) || seen[rule.ID] {
			return false
		}
		seen[rule.ID] = true
	}
	return true
}

func policyFingerprint(policy AssessmentPolicy) string {
	return fingerprint(struct {
		ProjectID, Name, SchemaVersion string
		Version                        int
		Rules                          []PolicyRule
	}{policy.ProjectID, policy.Name, policy.SchemaVersion, policy.Version, policy.Rules})
}

func validBaseline(baseline AssessmentBaseline) bool {
	return validID(baseline.ProjectID) && validFingerprint(baseline.SnapshotFingerprint) && validFingerprint(baseline.PolicyFingerprint) && validOptionalID(baseline.CampaignID) && validOptionalID(baseline.Description) && !baseline.SnapshotCreatedAt.IsZero() && !baseline.CreatedAt.IsZero() && validFingerprint(baseline.Fingerprint) && baseline.Fingerprint == baselineFingerprint(baseline)
}

func baselineFingerprint(baseline AssessmentBaseline) string {
	return fingerprint(struct {
		ProjectID, SnapshotFingerprint, PolicyFingerprint, CampaignID, Description string
		SnapshotCreatedAt, CreatedAt                                               time.Time
	}{baseline.ProjectID, baseline.SnapshotFingerprint, baseline.PolicyFingerprint, baseline.CampaignID, baseline.Description, baseline.SnapshotCreatedAt, baseline.CreatedAt})
}

func validRule(rule PolicyRule) bool {
	if !validID(rule.ID) || !supportedRule(rule.Type) || (rule.Operator != OperatorMaximum && rule.Operator != OperatorMinimum) || (rule.Effect != EffectFail && rule.Effect != EffectWarning && rule.Effect != EffectInformational) || rule.Threshold.Value < 0 || !validOptionalID(rule.Severity) || !validOptionalID(rule.Scope) {
		return false
	}
	if !validRuleUnit(rule.Type, rule.Threshold.Unit) {
		return false
	}
	if rule.Threshold.Unit == UnitBasisPoints && rule.Threshold.Value > 10000 {
		return false
	}
	return true
}

func validRuleUnit(ruleType RuleType, unit Unit) bool {
	switch ruleType {
	case RuleCoverage, RuleAssessmentCompletion, RuleEvidenceVerification:
		return unit == UnitBasisPoints
	case RuleEvidenceFreshness, RuleReproducibility:
		return unit == UnitCount || unit == UnitBasisPoints
	default:
		return unit == UnitCount
	}
}

func validEvaluationInput(input EvaluationInput) bool {
	if !validID(input.ProjectID) || input.EvaluatedAt.IsZero() || !validPolicy(input.Policy) || !validBaseline(input.Baseline) || input.Policy.ProjectID != input.ProjectID || input.Baseline.ProjectID != input.ProjectID || input.Baseline.PolicyFingerprint != input.Policy.Fingerprint || input.Baseline.SnapshotFingerprint != input.BaselineSnapshot.Fingerprint || input.BaselineSnapshot.ProjectID != input.ProjectID || input.CurrentSnapshot.ProjectID != input.ProjectID || input.Comparison.ProjectID != input.ProjectID || input.Comparison.BaselineFingerprint != input.BaselineSnapshot.Fingerprint || input.Comparison.CurrentFingerprint != input.CurrentSnapshot.Fingerprint {
		return false
	}
	expected, err := regression.Compare(input.BaselineSnapshot, input.CurrentSnapshot)
	return err == nil && expected.Fingerprint == input.Comparison.Fingerprint
}

// ValidateControlEvaluation verifies the canonical deterministic integrity of a
// persisted evaluation without re-running policy evaluation or mutating state.
func ValidateControlEvaluation(evaluation ControlEvaluation) bool {
	if !validID(evaluation.ProjectID) || !validFingerprint(evaluation.PolicyFingerprint) || !validFingerprint(evaluation.BaselineFingerprint) || !validFingerprint(evaluation.BaselineSnapshot) || !validFingerprint(evaluation.CurrentSnapshot) || !validFingerprint(evaluation.ComparisonFingerprint) || !validFingerprint(evaluation.Fingerprint) || evaluation.EvaluatedAt.IsZero() || len(evaluation.Decisions) > MaxRules || len(evaluation.Actions) > MaxActions {
		return false
	}
	decisions := map[string]ControlDecision{}
	summary := AssessmentSummary{}
	previousRuleID := ""
	for _, decision := range evaluation.Decisions {
		if !validControlDecision(decision, evaluation) || (previousRuleID != "" && previousRuleID >= decision.RuleID) {
			return false
		}
		previousRuleID = decision.RuleID
		decisions[decision.Fingerprint] = decision
		applySummary(&summary, decision.Status)
	}
	if summary != evaluation.Summary {
		return false
	}
	for _, action := range evaluation.Actions {
		decision, ok := decisions[action.SourceDecisionFingerprint]
		if !ok || !validAssessmentAction(action, evaluation.ProjectID, decision) {
			return false
		}
	}
	return evaluation.Fingerprint == controlEvaluationFingerprint(evaluation)
}

func validControlDecision(decision ControlDecision, evaluation ControlEvaluation) bool {
	return validID(decision.RuleID) && validDecisionStatus(decision.Status) && decision.ObservedValue >= 0 && decision.ExpectedValue >= 0 && (decision.Unit == UnitCount || decision.Unit == UnitBasisPoints) && validID(decision.Explanation) && decision.BaselineFingerprint == evaluation.BaselineSnapshot && decision.CurrentFingerprint == evaluation.CurrentSnapshot && decision.ComparisonFingerprint == evaluation.ComparisonFingerprint && validFingerprint(decision.Fingerprint) && decision.Fingerprint == controlDecisionFingerprint(decision)
}

func validAssessmentAction(action AssessmentAction, projectID string, decision ControlDecision) bool {
	if action.ProjectID != projectID || !validID(action.RuleID) || !validID(action.Kind) || !validID(action.Priority) || !validID(action.Rationale) || !validOptionalID(action.CampaignID) || action.Status != ActionRecommended || action.SourceDecisionFingerprint != decision.Fingerprint || !validFingerprint(action.ID) {
		return false
	}
	expectedID := fingerprint(struct{ ProjectID, RuleID, Kind, Decision string }{action.ProjectID, action.RuleID, action.Kind, decision.Fingerprint})
	if action.ID != expectedID {
		return false
	}
	if decision.Status == StatusFail {
		return action.Priority == "high"
	}
	return decision.Status == StatusWarning && action.Priority == "medium"
}

func validDecisionStatus(status DecisionStatus) bool {
	switch status {
	case StatusPass, StatusFail, StatusWarning, StatusInformational, StatusSkipped, StatusUnsupported, StatusUnknown:
		return true
	default:
		return false
	}
}

func controlDecisionFingerprint(decision ControlDecision) string {
	return fingerprint(struct {
		RuleID, Explanation, BaselineFingerprint, CurrentFingerprint, ComparisonFingerprint string
		Status                                                                              DecisionStatus
		ObservedValue, ExpectedValue                                                        int
		Unit                                                                                Unit
	}{decision.RuleID, decision.Explanation, decision.BaselineFingerprint, decision.CurrentFingerprint, decision.ComparisonFingerprint, decision.Status, decision.ObservedValue, decision.ExpectedValue, decision.Unit})
}

func controlEvaluationFingerprint(evaluation ControlEvaluation) string {
	return fingerprint(struct {
		ProjectID, PolicyFingerprint, BaselineFingerprint, BaselineSnapshot, CurrentSnapshot, ComparisonFingerprint string
		EvaluatedAt                                                                                                 time.Time
		Decisions                                                                                                   []ControlDecision
		Actions                                                                                                     []AssessmentAction
	}{evaluation.ProjectID, evaluation.PolicyFingerprint, evaluation.BaselineFingerprint, evaluation.BaselineSnapshot, evaluation.CurrentSnapshot, evaluation.ComparisonFingerprint, evaluation.EvaluatedAt.UTC(), evaluation.Decisions, evaluation.Actions})
}

func evaluateRule(rule PolicyRule, input EvaluationInput, evaluation ControlEvaluation) ControlDecision {
	observed, available, explanation := observedValue(rule, input)
	status := StatusPass
	if !available {
		if rule.Effect == EffectFail {
			status = StatusFail
		} else {
			status = StatusUnknown
		}
		explanation = "required recorded assessment data is unavailable"
	} else if !passes(rule.Operator, observed, rule.Threshold.Value) {
		switch rule.Effect {
		case EffectFail:
			status = StatusFail
		case EffectWarning:
			status = StatusWarning
		default:
			status = StatusInformational
		}
	}
	return ControlDecision{RuleID: rule.ID, Status: status, ObservedValue: observed, ExpectedValue: rule.Threshold.Value, Unit: rule.Threshold.Unit, Explanation: explanation, BaselineFingerprint: evaluation.BaselineSnapshot, CurrentFingerprint: evaluation.CurrentSnapshot, ComparisonFingerprint: evaluation.ComparisonFingerprint}
}

func observedValue(rule PolicyRule, input EvaluationInput) (int, bool, string) {
	changes := func(change regression.ChangeType) int {
		total := 0
		for _, item := range input.Comparison.Items {
			if item.Change == change {
				total++
			}
		}
		return total
	}
	if rule.Type == RuleCoverage || rule.Type == RuleAssessmentCompletion {
		if input.CurrentSnapshot.Coverage.Denominator == 0 {
			return 0, false, "coverage denominator is unknown"
		}
		return input.CurrentSnapshot.Coverage.Numerator * 10000 / input.CurrentSnapshot.Coverage.Denominator, true, "recorded assessment coverage in basis points"
	}
	switch rule.Type {
	case RuleFindingCount:
		return len(input.CurrentSnapshot.Findings), true, "recorded current finding count"
	case RuleFindingSeverity, RuleRiskBand:
		return countFindingsAtSeverity(input.CurrentSnapshot.Findings, rule.Severity), true, "recorded current finding severity count"
	case RuleNewFinding:
		return changes(regression.ChangeNewFinding), true, "recorded newly observed findings"
	case RuleResolvedFinding:
		return changes(regression.ChangeResolvedFinding), true, "recorded findings absent from current snapshot"
	case RuleReopenedFinding:
		return 0, false, "R18 does not record finding reopen state"
	case RuleRegression:
		return len(input.Comparison.Items), true, "recorded R18 regression item count"
	case RuleAttackSurfaceGrowth:
		return changes(regression.ChangeNewEndpoint) + changes(regression.ChangeNewParameter), true, "recorded attack-surface growth"
	case RuleAttackSurfaceReduction:
		return changes(regression.ChangeRemovedEndpoint) + changes(regression.ChangeRemovedParameter), true, "recorded attack-surface reduction"
	case RuleEvidenceFreshness:
		if rule.Threshold.Unit == UnitBasisPoints {
			return evidenceRate(input.CurrentSnapshot.Evidence, func(item regression.Evidence) bool { return item.Freshness == "stale" })
		}
		return changes(regression.ChangeEvidenceStale), true, "recorded stale evidence count"
	case RuleEvidenceVerification:
		return evidenceRate(input.CurrentSnapshot.Evidence, func(item regression.Evidence) bool { return item.Verification == "supported" })
	case RuleContradiction:
		return changes(regression.ChangeEvidenceContradiction), true, "recorded evidence contradiction count"
	case RuleReproducibility:
		if rule.Threshold.Unit == UnitBasisPoints {
			return evidenceRate(input.CurrentSnapshot.Evidence, func(item regression.Evidence) bool {
				return item.Reproducibility != "repeated_consistent" && item.Reproducibility != "repeatable"
			})
		}
		return countNonReproducible(input.CurrentSnapshot.Evidence), true, "recorded non-reproducible evidence count"
	case RuleMissingLineage:
		return countMissingLineage(input.CurrentSnapshot.Evidence), true, "recorded evidence lineage gaps"
	case RuleRiskScoreDelta, RuleTaskFailure:
		return 0, false, "the selected R18 snapshot does not retain this required metric"
	default:
		return 0, false, "unsupported policy rule"
	}
}

func passes(operator Operator, observed, expected int) bool {
	if operator == OperatorMinimum {
		return observed >= expected
	}
	return observed <= expected
}

func actionFor(rule PolicyRule, decision ControlDecision, campaignID, projectID string) AssessmentAction {
	kind := map[RuleType]string{RuleEvidenceFreshness: "refresh_evidence", RuleEvidenceVerification: "reverify_finding", RuleContradiction: "investigate_regression", RuleCoverage: "rerun_bounded_assessment", RuleAssessmentCompletion: "review_assessment_completion", RuleAttackSurfaceGrowth: "inspect_attack_surface", RuleNewFinding: "reverify_finding"}[rule.Type]
	if kind == "" {
		kind = "review_policy"
	}
	priority := "medium"
	if decision.Status == StatusFail {
		priority = "high"
	}
	return AssessmentAction{ID: fingerprint(struct{ ProjectID, RuleID, Kind, Decision string }{projectID, rule.ID, kind, decision.Fingerprint}), ProjectID: projectID, RuleID: rule.ID, Kind: kind, Priority: priority, Rationale: decision.Explanation, CampaignID: campaignID, Status: ActionRecommended, SourceDecisionFingerprint: decision.Fingerprint}
}

func applySummary(summary *AssessmentSummary, status DecisionStatus) {
	switch status {
	case StatusPass:
		summary.Passed++
	case StatusFail:
		summary.Failed++
	case StatusWarning:
		summary.Warnings++
	case StatusInformational:
		summary.Informational++
	case StatusSkipped:
		summary.Skipped++
	case StatusUnsupported:
		summary.Unsupported++
	case StatusUnknown:
		summary.Unknown++
	}
}

func supportedRule(rule RuleType) bool {
	switch rule {
	case RuleFindingCount, RuleFindingSeverity, RuleNewFinding, RuleResolvedFinding, RuleReopenedFinding, RuleRegression, RuleAttackSurfaceGrowth, RuleAttackSurfaceReduction, RuleEvidenceFreshness, RuleEvidenceVerification, RuleContradiction, RuleCoverage, RuleReproducibility, RuleMissingLineage, RuleRiskBand, RuleRiskScoreDelta, RuleTaskFailure, RuleAssessmentCompletion:
		return true
	default:
		return false
	}
}

func countFindingsAtSeverity(findings []regression.Finding, severity string) int {
	if severity == "" {
		return len(findings)
	}
	total := 0
	for _, finding := range findings {
		if strings.EqualFold(finding.Severity, severity) || strings.EqualFold(finding.RiskBand, severity) {
			total++
		}
	}
	return total
}

func evidenceRate(evidence []regression.Evidence, matches func(regression.Evidence) bool) (int, bool, string) {
	if len(evidence) == 0 {
		return 0, false, "recorded evidence denominator is unknown"
	}
	matched := 0
	for _, item := range evidence {
		if matches(item) {
			matched++
		}
	}
	return matched * 10000 / len(evidence), true, "recorded evidence rate in basis points"
}

func countNonReproducible(evidence []regression.Evidence) int {
	total := 0
	for _, item := range evidence {
		if item.Reproducibility != "repeated_consistent" && item.Reproducibility != "repeatable" {
			total++
		}
	}
	return total
}

func countMissingLineage(evidence []regression.Evidence) int {
	total := 0
	for _, item := range evidence {
		total += len(item.Gaps)
	}
	return total
}

func validID(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= MaxStringBytes && !secretLike(value)
}

func validOptionalID(value string) bool { return value == "" || validID(value) }

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func secretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "cookie", "authorization", "api_key", "apikey", "token", "secret", "bearer", "session=", "@"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func fingerprint(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
