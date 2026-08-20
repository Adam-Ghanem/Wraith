package reportmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const SchemaVersion = "r16.v1"

type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	RiskScore int    `json:"risk_score"`
}

type CoverageMetric struct {
	Definition  string `json:"definition"`
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
}

// EvidenceDetail is a read-only projection of the latest persisted R17 correlation
// for one finding. It never changes R11.5 finding state or risk.
type EvidenceDetail struct {
	FindingID       string   `json:"finding_id"`
	Verification    string   `json:"verification"`
	Freshness       string   `json:"freshness"`
	Reproducibility string   `json:"reproducibility"`
	Gaps            []string `json:"gaps"`
	Contradictions  []string `json:"contradictions"`
}

// EvidenceVerification deliberately contains only report-safe correlation output.
// A zero-value instance means no persisted R17 correlation snapshots are available.
type EvidenceVerification struct {
	Details []EvidenceDetail `json:"details"`
}

// RegressionDetail is a report-safe projection of one persisted R18 comparison
// item. It describes recorded change intelligence only; it never alters the
// underlying finding, risk, campaign, or evidence owner state.
type RegressionDetail struct {
	Category   string `json:"category"`
	Change     string `json:"change_type"`
	Subject    string `json:"subject_fingerprint"`
	Impact     string `json:"impact"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type RegressionIntelligence struct {
	ComparisonFingerprint string             `json:"comparison_fingerprint,omitempty"`
	BaselineFingerprint   string             `json:"baseline_fingerprint,omitempty"`
	CurrentFingerprint    string             `json:"current_fingerprint,omitempty"`
	BaselineCreatedAt     string             `json:"baseline_created_at,omitempty"`
	CurrentCreatedAt      string             `json:"current_created_at,omitempty"`
	ComparedAt            string             `json:"compared_at,omitempty"`
	Details               []RegressionDetail `json:"details"`
}

type AssessmentDecision struct {
	RuleID        string `json:"rule_id"`
	Status        string `json:"status"`
	ObservedValue int    `json:"observed_value"`
	ExpectedValue int    `json:"expected_value"`
	Unit          string `json:"unit"`
	Explanation   string `json:"explanation"`
}

type AssessmentAction struct {
	RuleID    string `json:"rule_id"`
	Kind      string `json:"kind"`
	Priority  string `json:"priority"`
	Rationale string `json:"rationale"`
}

// AssessmentControl is a report-safe, read-only R19 projection. It cannot
// execute actions or change existing owner lifecycle state.
type AssessmentControl struct {
	EvaluationFingerprint      string               `json:"evaluation_fingerprint,omitempty"`
	PolicyFingerprint          string               `json:"policy_fingerprint,omitempty"`
	BaselineFingerprint        string               `json:"baseline_fingerprint,omitempty"`
	CurrentSnapshotFingerprint string               `json:"current_snapshot_fingerprint,omitempty"`
	Status                     string               `json:"status,omitempty"`
	FailedRules                int                  `json:"failed_rules"`
	Decisions                  []AssessmentDecision `json:"decisions"`
	Actions                    []AssessmentAction   `json:"actions"`
}

// GovernanceDecision is a report-safe R20 operational decision/event lineage.
// It records local operator treatment only and never implies remediation.
type GovernanceDecision struct {
	RecommendationFingerprint string `json:"recommendation_fingerprint"`
	State                     string `json:"state"`
	PreviousState             string `json:"previous_state"`
	EventType                 string `json:"event_type"`
	Actor                     string `json:"actor"`
	Reason                    string `json:"reason"`
	OccurredAt                string `json:"occurred_at"`
	EventFingerprint          string `json:"event_fingerprint"`
}

// GovernanceControl is a read-only R20 projection for aggregate executive
// posture and technical audit lineage. It cannot execute a recommendation.
type GovernanceControl struct {
	Overall               string               `json:"overall,omitempty"`
	PolicyFingerprint     string               `json:"policy_fingerprint,omitempty"`
	BaselineFingerprint   string               `json:"baseline_fingerprint,omitempty"`
	EvaluationFingerprint string               `json:"evaluation_fingerprint,omitempty"`
	ComparisonFingerprint string               `json:"comparison_fingerprint,omitempty"`
	UnresolvedActions     int                  `json:"unresolved_actions"`
	StaleReasons          []string             `json:"stale_reasons"`
	Limitations           []string             `json:"limitations"`
	Decisions             []GovernanceDecision `json:"decisions"`
}

// AnalyticsControl is a read-only R21 historical-intelligence projection. It
// is not a finding, risk score, execution result, or remediation assertion.
type AnalyticsControl struct {
	OverallTrend        string   `json:"overall_trend,omitempty"`
	HealthIndex         int      `json:"assessment_health_index"`
	Health              string   `json:"assessment_health,omitempty"`
	RegressionCount     int      `json:"regression_count"`
	GovernanceBacklog   int      `json:"governance_backlog"`
	StaleEvidence       int      `json:"stale_evidence"`
	DataQuality         string   `json:"data_quality,omitempty"`
	SnapshotFingerprint string   `json:"snapshot_fingerprint,omitempty"`
	Limitations         []string `json:"limitations"`
}

// DecisionFactor is a report-safe projection of one R22 factor. It holds only
// fixed type, bounded weight, and safe lineage metadata.
type DecisionFactor struct {
	Type              string `json:"type"`
	Weight            int    `json:"weight"`
	SourceFingerprint string `json:"source_fingerprint"`
}

type DecisionConstraint struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// DecisionRecommendation is descriptive only. A valid report projection must
// retain NonExecuting=true, so it cannot be read as an execution record.
type DecisionRecommendation struct {
	ID, Fingerprint, Priority, State, Action, Confidence, Quality string
	NonExecuting                                                  bool
	Reasons                                                       []string
	Factors                                                       []DecisionFactor
	Constraints                                                   []DecisionConstraint
	Lineage                                                       []string
}

// DecisionIntelligenceControl is the R22 read-only executive and technical
// decision projection. It never creates work, alters a lifecycle, or claims
// that a recommended action occurred.
type DecisionIntelligenceControl struct {
	Status, SnapshotFingerprint, DataQuality, Confidence       string
	PriorityP0, PriorityP1, PriorityP2, PriorityP3, PriorityP4 int
	GovernanceBlockers, Limitations                            []string
	Recommendations                                            []DecisionRecommendation
}

func (coverage CoverageMetric) Display() string {
	if coverage.Denominator == 0 {
		return "N/A"
	}
	return "recorded"
}

type SnapshotInput struct {
	ProjectID, CampaignID, ScopeVersion, SchemaVersion string
	CampaignStatus, Profile, Target                    string
	Findings                                           []Finding
	Limitations                                        []string
	Coverage                                           CoverageMetric
	Evidence                                           EvidenceVerification
	Regression                                         RegressionIntelligence
	Assessment                                         AssessmentControl
	Governance                                         GovernanceControl
	Analytics                                          AnalyticsControl
	Decision                                           DecisionIntelligenceControl
}

type Snapshot struct {
	ProjectID      string                      `json:"project_id"`
	CampaignID     string                      `json:"campaign_id,omitempty"`
	CampaignStatus string                      `json:"campaign_status,omitempty"`
	Profile        string                      `json:"profile,omitempty"`
	Target         string                      `json:"target,omitempty"`
	ScopeVersion   string                      `json:"scope_version"`
	SchemaVersion  string                      `json:"schema_version"`
	Fingerprint    string                      `json:"fingerprint"`
	Findings       []Finding                   `json:"findings"`
	Limitations    []string                    `json:"limitations"`
	Coverage       CoverageMetric              `json:"coverage"`
	Evidence       EvidenceVerification        `json:"evidence_verification"`
	Regression     RegressionIntelligence      `json:"security_regression"`
	Assessment     AssessmentControl           `json:"continuous_assessment"`
	Governance     GovernanceControl           `json:"continuous_assessment_governance"`
	Analytics      AnalyticsControl            `json:"continuous_assessment_analytics"`
	Decision       DecisionIntelligenceControl `json:"continuous_assessment_decision_intelligence"`
}

func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.ScopeVersion) == "" || secretLike(input.ProjectID) || secretLike(input.CampaignID) || secretLike(input.ScopeVersion) || secretLike(input.Target) || input.SchemaVersion != SchemaVersion || input.Coverage.Numerator < 0 || input.Coverage.Denominator < 0 || input.Coverage.Numerator > input.Coverage.Denominator || strings.TrimSpace(input.Coverage.Definition) == "" {
		return Snapshot{}, errors.New("invalid report snapshot")
	}
	snapshot := Snapshot{ProjectID: input.ProjectID, CampaignID: input.CampaignID, CampaignStatus: input.CampaignStatus, Profile: input.Profile, Target: input.Target, ScopeVersion: input.ScopeVersion, SchemaVersion: input.SchemaVersion, Findings: append([]Finding{}, input.Findings...), Limitations: append([]string{}, input.Limitations...), Coverage: input.Coverage, Evidence: EvidenceVerification{Details: append([]EvidenceDetail{}, input.Evidence.Details...)}, Regression: RegressionIntelligence{ComparisonFingerprint: input.Regression.ComparisonFingerprint, BaselineFingerprint: input.Regression.BaselineFingerprint, CurrentFingerprint: input.Regression.CurrentFingerprint, BaselineCreatedAt: input.Regression.BaselineCreatedAt, CurrentCreatedAt: input.Regression.CurrentCreatedAt, ComparedAt: input.Regression.ComparedAt, Details: append([]RegressionDetail{}, input.Regression.Details...)}, Assessment: AssessmentControl{EvaluationFingerprint: input.Assessment.EvaluationFingerprint, PolicyFingerprint: input.Assessment.PolicyFingerprint, BaselineFingerprint: input.Assessment.BaselineFingerprint, CurrentSnapshotFingerprint: input.Assessment.CurrentSnapshotFingerprint, Status: input.Assessment.Status, FailedRules: input.Assessment.FailedRules, Decisions: append([]AssessmentDecision{}, input.Assessment.Decisions...), Actions: append([]AssessmentAction{}, input.Assessment.Actions...)}, Governance: GovernanceControl{Overall: input.Governance.Overall, PolicyFingerprint: input.Governance.PolicyFingerprint, BaselineFingerprint: input.Governance.BaselineFingerprint, EvaluationFingerprint: input.Governance.EvaluationFingerprint, ComparisonFingerprint: input.Governance.ComparisonFingerprint, UnresolvedActions: input.Governance.UnresolvedActions, StaleReasons: append([]string{}, input.Governance.StaleReasons...), Limitations: append([]string{}, input.Governance.Limitations...), Decisions: append([]GovernanceDecision{}, input.Governance.Decisions...)}}
	snapshot.Analytics = AnalyticsControl{OverallTrend: input.Analytics.OverallTrend, HealthIndex: input.Analytics.HealthIndex, Health: input.Analytics.Health, RegressionCount: input.Analytics.RegressionCount, GovernanceBacklog: input.Analytics.GovernanceBacklog, StaleEvidence: input.Analytics.StaleEvidence, DataQuality: input.Analytics.DataQuality, SnapshotFingerprint: input.Analytics.SnapshotFingerprint, Limitations: append([]string{}, input.Analytics.Limitations...)}
	snapshot.Decision = DecisionIntelligenceControl{Status: input.Decision.Status, SnapshotFingerprint: input.Decision.SnapshotFingerprint, DataQuality: input.Decision.DataQuality, Confidence: input.Decision.Confidence, PriorityP0: input.Decision.PriorityP0, PriorityP1: input.Decision.PriorityP1, PriorityP2: input.Decision.PriorityP2, PriorityP3: input.Decision.PriorityP3, PriorityP4: input.Decision.PriorityP4, GovernanceBlockers: append([]string{}, input.Decision.GovernanceBlockers...), Limitations: append([]string{}, input.Decision.Limitations...), Recommendations: append([]DecisionRecommendation{}, input.Decision.Recommendations...)}
	for _, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.ID) == "" || secretLike(finding.ID) || finding.RiskScore < 0 || finding.RiskScore > 100 {
			return Snapshot{}, errors.New("invalid report finding")
		}
	}
	for _, limitation := range snapshot.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return Snapshot{}, errors.New("invalid report limitation")
		}
	}
	for detailIndex := range snapshot.Evidence.Details {
		detail := &snapshot.Evidence.Details[detailIndex]
		if strings.TrimSpace(detail.FindingID) == "" || secretLike(detail.FindingID) || strings.TrimSpace(detail.Verification) == "" || strings.TrimSpace(detail.Freshness) == "" || strings.TrimSpace(detail.Reproducibility) == "" {
			return Snapshot{}, errors.New("invalid report evidence detail")
		}
		detail.Gaps = append([]string{}, detail.Gaps...)
		detail.Contradictions = append([]string{}, detail.Contradictions...)
		for _, code := range append(append([]string{}, detail.Gaps...), detail.Contradictions...) {
			if strings.TrimSpace(code) == "" || secretLike(code) {
				return Snapshot{}, errors.New("invalid report evidence detail")
			}
		}
		sort.Strings(detail.Gaps)
		sort.Strings(detail.Contradictions)
	}
	for _, value := range []string{snapshot.Regression.ComparisonFingerprint, snapshot.Regression.BaselineFingerprint, snapshot.Regression.CurrentFingerprint, snapshot.Regression.BaselineCreatedAt, snapshot.Regression.CurrentCreatedAt, snapshot.Regression.ComparedAt} {
		if value != "" && secretLike(value) {
			return Snapshot{}, errors.New("invalid report regression")
		}
	}
	for _, detail := range snapshot.Regression.Details {
		for _, value := range []string{detail.Category, detail.Change, detail.Subject, detail.Impact, detail.Confidence, detail.Reason} {
			if strings.TrimSpace(value) == "" || secretLike(value) {
				return Snapshot{}, errors.New("invalid report regression")
			}
		}
	}
	if snapshot.Assessment.FailedRules < 0 {
		return Snapshot{}, errors.New("invalid report assessment control")
	}
	for _, value := range []string{snapshot.Assessment.EvaluationFingerprint, snapshot.Assessment.PolicyFingerprint, snapshot.Assessment.BaselineFingerprint, snapshot.Assessment.CurrentSnapshotFingerprint, snapshot.Assessment.Status} {
		if value != "" && secretLike(value) {
			return Snapshot{}, errors.New("invalid report assessment control")
		}
	}
	for _, decision := range snapshot.Assessment.Decisions {
		if decision.ObservedValue < 0 || decision.ExpectedValue < 0 {
			return Snapshot{}, errors.New("invalid report assessment control")
		}
		for _, value := range []string{decision.RuleID, decision.Status, decision.Unit, decision.Explanation} {
			if strings.TrimSpace(value) == "" || secretLike(value) {
				return Snapshot{}, errors.New("invalid report assessment control")
			}
		}
	}
	for _, action := range snapshot.Assessment.Actions {
		for _, value := range []string{action.RuleID, action.Kind, action.Priority, action.Rationale} {
			if strings.TrimSpace(value) == "" || secretLike(value) {
				return Snapshot{}, errors.New("invalid report assessment control")
			}
		}
	}
	if snapshot.Governance.UnresolvedActions < 0 {
		return Snapshot{}, errors.New("invalid report governance control")
	}
	for _, value := range []string{snapshot.Governance.Overall, snapshot.Governance.PolicyFingerprint, snapshot.Governance.BaselineFingerprint, snapshot.Governance.EvaluationFingerprint, snapshot.Governance.ComparisonFingerprint} {
		if value != "" && secretLike(value) {
			return Snapshot{}, errors.New("invalid report governance control")
		}
	}
	for _, value := range append(append([]string{}, snapshot.Governance.StaleReasons...), snapshot.Governance.Limitations...) {
		if strings.TrimSpace(value) == "" || secretLike(value) {
			return Snapshot{}, errors.New("invalid report governance control")
		}
	}
	for _, decision := range snapshot.Governance.Decisions {
		for _, value := range []string{decision.RecommendationFingerprint, decision.State, decision.PreviousState, decision.EventType, decision.Actor, decision.Reason, decision.OccurredAt, decision.EventFingerprint} {
			if strings.TrimSpace(value) == "" || secretLike(value) {
				return Snapshot{}, errors.New("invalid report governance control")
			}
		}
	}
	if snapshot.Analytics.HealthIndex < 0 || snapshot.Analytics.HealthIndex > 100 || snapshot.Analytics.RegressionCount < 0 || snapshot.Analytics.GovernanceBacklog < 0 || snapshot.Analytics.StaleEvidence < 0 {
		return Snapshot{}, errors.New("invalid report analytics control")
	}
	for _, value := range append([]string{snapshot.Analytics.OverallTrend, snapshot.Analytics.Health, snapshot.Analytics.DataQuality, snapshot.Analytics.SnapshotFingerprint}, snapshot.Analytics.Limitations...) {
		if value != "" && secretLike(value) {
			return Snapshot{}, errors.New("invalid report analytics control")
		}
	}
	if snapshot.Decision.PriorityP0 < 0 || snapshot.Decision.PriorityP1 < 0 || snapshot.Decision.PriorityP2 < 0 || snapshot.Decision.PriorityP3 < 0 || snapshot.Decision.PriorityP4 < 0 {
		return Snapshot{}, errors.New("invalid report decision control")
	}
	for _, value := range append(append([]string{snapshot.Decision.Status, snapshot.Decision.SnapshotFingerprint, snapshot.Decision.DataQuality, snapshot.Decision.Confidence}, snapshot.Decision.GovernanceBlockers...), snapshot.Decision.Limitations...) {
		if value != "" && secretLike(value) {
			return Snapshot{}, errors.New("invalid report decision control")
		}
	}
	for recommendationIndex := range snapshot.Decision.Recommendations {
		recommendation := &snapshot.Decision.Recommendations[recommendationIndex]
		for _, value := range []string{recommendation.ID, recommendation.Fingerprint, recommendation.Priority, recommendation.State, recommendation.Action, recommendation.Confidence, recommendation.Quality} {
			if strings.TrimSpace(value) == "" || secretLike(value) {
				return Snapshot{}, errors.New("invalid report decision control")
			}
		}
		if !recommendation.NonExecuting || len(recommendation.Reasons) == 0 {
			return Snapshot{}, errors.New("invalid report decision control")
		}
		for _, reason := range recommendation.Reasons {
			if strings.TrimSpace(reason) == "" || secretLike(reason) {
				return Snapshot{}, errors.New("invalid report decision control")
			}
		}
		for _, factor := range recommendation.Factors {
			if strings.TrimSpace(factor.Type) == "" || factor.Weight < 0 || factor.Weight > 100 || strings.TrimSpace(factor.SourceFingerprint) == "" || secretLike(factor.Type) || secretLike(factor.SourceFingerprint) {
				return Snapshot{}, errors.New("invalid report decision control")
			}
		}
		for _, constraint := range recommendation.Constraints {
			if strings.TrimSpace(constraint.Type) == "" || strings.TrimSpace(constraint.Reason) == "" || secretLike(constraint.Type) || secretLike(constraint.Reason) {
				return Snapshot{}, errors.New("invalid report decision control")
			}
		}
		for _, source := range recommendation.Lineage {
			if strings.TrimSpace(source) == "" || secretLike(source) {
				return Snapshot{}, errors.New("invalid report decision control")
			}
		}
		recommendation.Reasons = append([]string{}, recommendation.Reasons...)
		recommendation.Factors = append([]DecisionFactor{}, recommendation.Factors...)
		recommendation.Constraints = append([]DecisionConstraint{}, recommendation.Constraints...)
		recommendation.Lineage = append([]string{}, recommendation.Lineage...)
		sort.Strings(recommendation.Reasons)
		sort.Strings(recommendation.Lineage)
		sort.Slice(recommendation.Factors, func(left, right int) bool {
			return recommendation.Factors[left].Type+"\x00"+recommendation.Factors[left].SourceFingerprint < recommendation.Factors[right].Type+"\x00"+recommendation.Factors[right].SourceFingerprint
		})
		sort.Slice(recommendation.Constraints, func(left, right int) bool {
			return recommendation.Constraints[left].Type+"\x00"+recommendation.Constraints[left].Reason < recommendation.Constraints[right].Type+"\x00"+recommendation.Constraints[right].Reason
		})
	}
	sort.Slice(snapshot.Findings, func(left, right int) bool { return snapshot.Findings[left].ID < snapshot.Findings[right].ID })
	sort.Strings(snapshot.Limitations)
	sort.Slice(snapshot.Evidence.Details, func(left, right int) bool {
		return snapshot.Evidence.Details[left].FindingID < snapshot.Evidence.Details[right].FindingID
	})
	sort.Slice(snapshot.Regression.Details, func(left, right int) bool {
		leftDetail, rightDetail := snapshot.Regression.Details[left], snapshot.Regression.Details[right]
		return leftDetail.Category+"\x00"+leftDetail.Impact+"\x00"+leftDetail.Subject+"\x00"+leftDetail.Change+"\x00"+leftDetail.Reason < rightDetail.Category+"\x00"+rightDetail.Impact+"\x00"+rightDetail.Subject+"\x00"+rightDetail.Change+"\x00"+rightDetail.Reason
	})
	sort.Slice(snapshot.Assessment.Decisions, func(left, right int) bool {
		return snapshot.Assessment.Decisions[left].RuleID < snapshot.Assessment.Decisions[right].RuleID
	})
	sort.Slice(snapshot.Assessment.Actions, func(left, right int) bool {
		leftAction, rightAction := snapshot.Assessment.Actions[left], snapshot.Assessment.Actions[right]
		return leftAction.RuleID+"\x00"+leftAction.Kind+"\x00"+leftAction.Priority < rightAction.RuleID+"\x00"+rightAction.Kind+"\x00"+rightAction.Priority
	})
	sort.Strings(snapshot.Governance.StaleReasons)
	sort.Strings(snapshot.Governance.Limitations)
	sort.Strings(snapshot.Analytics.Limitations)
	sort.Strings(snapshot.Decision.GovernanceBlockers)
	sort.Strings(snapshot.Decision.Limitations)
	sort.Slice(snapshot.Decision.Recommendations, func(left, right int) bool {
		return snapshot.Decision.Recommendations[left].Priority+"\x00"+snapshot.Decision.Recommendations[left].ID < snapshot.Decision.Recommendations[right].Priority+"\x00"+snapshot.Decision.Recommendations[right].ID
	})
	sort.Slice(snapshot.Governance.Decisions, func(left, right int) bool {
		leftDecision, rightDecision := snapshot.Governance.Decisions[left], snapshot.Governance.Decisions[right]
		return leftDecision.RecommendationFingerprint+"\x00"+leftDecision.OccurredAt+"\x00"+leftDecision.EventFingerprint < rightDecision.RecommendationFingerprint+"\x00"+rightDecision.OccurredAt+"\x00"+rightDecision.EventFingerprint
	})
	normalized, err := json.Marshal(struct {
		ProjectID, CampaignID, CampaignStatus, Profile, Target, ScopeVersion, SchemaVersion string
		Findings                                                                            []Finding
		Limitations                                                                         []string
		Coverage                                                                            CoverageMetric
		Evidence                                                                            EvidenceVerification
		Regression                                                                          RegressionIntelligence
		Assessment                                                                          AssessmentControl
		Governance                                                                          GovernanceControl
		Analytics                                                                           AnalyticsControl
		Decision                                                                            DecisionIntelligenceControl
	}{snapshot.ProjectID, snapshot.CampaignID, snapshot.CampaignStatus, snapshot.Profile, snapshot.Target, snapshot.ScopeVersion, snapshot.SchemaVersion, snapshot.Findings, snapshot.Limitations, snapshot.Coverage, snapshot.Evidence, snapshot.Regression, snapshot.Assessment, snapshot.Governance, snapshot.Analytics, snapshot.Decision})
	if err != nil {
		return Snapshot{}, err
	}
	sum := sha256.Sum256(normalized)
	snapshot.Fingerprint = hex.EncodeToString(sum[:])
	return snapshot, nil
}

func secretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "cookie", "authorization", "api_key", "apikey", "token", "secret", "bearer", "session="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
