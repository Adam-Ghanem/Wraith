// Package datagovernance is the pure, deterministic T7 authority for policy,
// consumer decisions, and retention state. Raw-value screening and redaction
// remain owned by internal/dataclassification; T1-T6 remain separate owners.
package datagovernance

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

var (
	ErrGovernanceUnavailable      = errors.New("data governance is unavailable")
	ErrClassificationRequired     = errors.New("data classification is required")
	ErrClassificationInvalid      = errors.New("data classification is invalid")
	ErrSecretDetected             = errors.New("secret-like governance input is forbidden")
	ErrPolicyInvalid              = errors.New("data governance policy is invalid")
	ErrPolicyExpired              = errors.New("data governance policy is expired")
	ErrPolicyMismatch             = errors.New("data governance policy does not match the request")
	ErrProjectMismatch            = errors.New("data governance project mismatch")
	ErrRetentionViolation         = errors.New("data retention record is invalid")
	ErrConsumerDenied             = errors.New("data consumer is not allowed")
	ErrGovernanceDenied           = errors.New("data governance decision is denied")
	ErrGovernanceAuditFailed      = errors.New("data governance audit failed")
	ErrGovernanceIntegrityFailure = errors.New("data governance integrity validation failed")
)

const PolicyVersion = "t7.governance.v1"

type Consumer string

const (
	ConsumerLocalStorage    Consumer = "local_storage"
	ConsumerTechnicalReport Consumer = "technical_report"
	ConsumerExecutiveReport Consumer = "executive_report"
	ConsumerCLIOutput       Consumer = "cli_output"
	ConsumerJSONExport      Consumer = "json_export"
	ConsumerMarkdownExport  Consumer = "markdown_export"
	ConsumerHTMLExport      Consumer = "html_export"
	ConsumerAuditLog        Consumer = "audit_log"
	ConsumerAnalytics       Consumer = "analytics"
	ConsumerEgress          Consumer = "egress"
)

type Subject string

const (
	SubjectTarget        Subject = "target"
	SubjectHostname      Subject = "hostname"
	SubjectIPAddress     Subject = "ip_address"
	SubjectURL           Subject = "url"
	SubjectEndpoint      Subject = "endpoint"
	SubjectParameter     Subject = "parameter"
	SubjectRequestMeta   Subject = "request_metadata"
	SubjectResponseMeta  Subject = "response_metadata"
	SubjectFinding       Subject = "finding"
	SubjectObservation   Subject = "observation"
	SubjectEvidence      Subject = "evidence"
	SubjectValidation    Subject = "validation_result"
	SubjectCampaign      Subject = "campaign"
	SubjectCampaignTask  Subject = "campaign_task"
	SubjectTaskResult    Subject = "task_result"
	SubjectRiskScore     Subject = "risk_score"
	SubjectReport        Subject = "report"
	SubjectAuthorization Subject = "authorization_reference"
	SubjectScope         Subject = "scope_reference"
	SubjectAuditEvent    Subject = "audit_event"
	SubjectSnapshot      Subject = "snapshot"
	SubjectAnalytics     Subject = "analytics_result"
	SubjectRegression    Subject = "regression_result"
	SubjectDecision      Subject = "governance_decision"
)

type DecisionAction string

const (
	DecisionAllow             DecisionAction = "allow"
	DecisionAllowRedacted     DecisionAction = "allow_redacted"
	DecisionAllowHashed       DecisionAction = "allow_hashed"
	DecisionAllowMetadataOnly DecisionAction = "allow_metadata_only"
	DecisionDeny              DecisionAction = "deny"
	DecisionExpire            DecisionAction = "expire"
	DecisionDelete            DecisionAction = "delete"
)

type RetentionStatus string

const (
	RetentionActive           RetentionStatus = "active"
	RetentionHeld             RetentionStatus = "held"
	RetentionExpired          RetentionStatus = "expired"
	RetentionDeletionEligible RetentionStatus = "deletion_eligible"
)

type Rule struct {
	Consumer  Consumer                 `json:"consumer"`
	Maximum   dataclassification.Level `json:"maximum_classification"`
	Retention time.Duration            `json:"retention"`
}

type PolicyInput struct {
	ProjectID string
	Version   string
	Rules     []Rule
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Policy struct {
	ProjectID     string    `json:"project_id"`
	Version       string    `json:"version"`
	Rules         []Rule    `json:"rules"`
	PolicyVersion string    `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Fingerprint   string    `json:"fingerprint"`
}

type EvaluationInput struct {
	Policy         Policy
	ProjectID      string
	Subject        Subject
	Classification dataclassification.Level
	Consumer       Consumer
	OccurredAt     time.Time
}

type Decision struct {
	Action            DecisionAction           `json:"action"`
	ReasonCode        string                   `json:"reason_code"`
	PolicyVersion     string                   `json:"policy_version"`
	PolicyFingerprint string                   `json:"policy_fingerprint"`
	Classification    dataclassification.Level `json:"classification"`
	Subject           Subject                  `json:"subject"`
	Consumer          Consumer                 `json:"consumer"`
	ProjectID         string                   `json:"project_id"`
	OccurredAt        time.Time                `json:"occurred_at"`
	Fingerprint       string                   `json:"fingerprint"`
}

type RetentionInput struct {
	ProjectID        string
	Policy           Policy
	SubjectReference string
	CreatedAt        time.Time
	RetainUntil      time.Time
	Hold             bool
}

type RetentionRecord struct {
	ProjectID         string    `json:"project_id"`
	PolicyVersion     string    `json:"policy_version"`
	PolicyFingerprint string    `json:"policy_fingerprint"`
	SubjectReference  string    `json:"subject_reference"`
	CreatedAt         time.Time `json:"created_at"`
	RetainUntil       time.Time `json:"retain_until"`
	Hold              bool      `json:"hold"`
	Fingerprint       string    `json:"fingerprint"`
}

func NewPolicy(input PolicyInput) (Policy, error) {
	policy := Policy{
		ProjectID:     strings.TrimSpace(input.ProjectID),
		Version:       strings.TrimSpace(input.Version),
		Rules:         append([]Rule(nil), input.Rules...),
		PolicyVersion: PolicyVersion,
		CreatedAt:     input.CreatedAt.UTC(),
		ExpiresAt:     input.ExpiresAt.UTC(),
	}
	if !validSafeIdentifier(policy.ProjectID) || !validSafeIdentifier(policy.Version) || policy.CreatedAt.IsZero() || len(policy.Rules) == 0 || len(policy.Rules) > 32 || (!policy.ExpiresAt.IsZero() && !policy.ExpiresAt.After(policy.CreatedAt)) {
		return Policy{}, ErrPolicyInvalid
	}
	sort.Slice(policy.Rules, func(left, right int) bool { return policy.Rules[left].Consumer < policy.Rules[right].Consumer })
	for index, rule := range policy.Rules {
		if !validRule(rule) || index > 0 && policy.Rules[index-1].Consumer == rule.Consumer {
			return Policy{}, ErrPolicyInvalid
		}
	}
	policy.Fingerprint = policyFingerprint(policy)
	return policy, nil
}

func ValidatePolicy(policy Policy) error {
	canonical, err := NewPolicy(PolicyInput{ProjectID: policy.ProjectID, Version: policy.Version, Rules: policy.Rules, CreatedAt: policy.CreatedAt, ExpiresAt: policy.ExpiresAt})
	if err != nil {
		return err
	}
	if policy.PolicyVersion != PolicyVersion || policy.Fingerprint != canonical.Fingerprint {
		return ErrGovernanceIntegrityFailure
	}
	return nil
}

func Evaluate(input EvaluationInput) (Decision, error) {
	if err := ValidatePolicy(input.Policy); err != nil {
		return Decision{}, err
	}
	projectID := strings.TrimSpace(input.ProjectID)
	if projectID != input.Policy.ProjectID {
		return Decision{}, ErrProjectMismatch
	}
	if !validSubject(input.Subject) || !validConsumer(input.Consumer) || !dataclassification.ValidLevel(string(input.Classification)) || input.OccurredAt.UTC().IsZero() {
		return Decision{}, ErrClassificationInvalid
	}
	if !input.Policy.ExpiresAt.IsZero() && !input.Policy.ExpiresAt.After(input.OccurredAt.UTC()) {
		return Decision{}, ErrPolicyExpired
	}
	rule, exists := findRule(input.Policy.Rules, input.Consumer)
	if !exists {
		return Decision{}, ErrConsumerDenied
	}
	decision := Decision{PolicyVersion: input.Policy.PolicyVersion, PolicyFingerprint: input.Policy.Fingerprint, Classification: input.Classification, Subject: input.Subject, Consumer: input.Consumer, ProjectID: projectID, OccurredAt: input.OccurredAt.UTC()}
	decision.Action, decision.ReasonCode = decide(rule, input)
	decision.Fingerprint = decisionFingerprint(decision)
	return decision, nil
}

// ValidateDecision recomputes the deterministic fingerprint and checks every
// safe identifier before a stored or cross-package governance decision is used.
func ValidateDecision(decision Decision) error {
	if !validDecisionAction(decision.Action) || !validSafeIdentifier(decision.ReasonCode) || decision.PolicyVersion != PolicyVersion || !validFingerprint(decision.PolicyFingerprint) || !dataclassification.ValidLevel(string(decision.Classification)) || !validSubject(decision.Subject) || !validConsumer(decision.Consumer) || !validSafeIdentifier(decision.ProjectID) || decision.OccurredAt.UTC().IsZero() || !validFingerprint(decision.Fingerprint) {
		return ErrGovernanceIntegrityFailure
	}
	if decision.Fingerprint != decisionFingerprint(decision) {
		return ErrGovernanceIntegrityFailure
	}
	return nil
}

func NewRetentionRecord(input RetentionInput) (RetentionRecord, error) {
	if err := ValidatePolicy(input.Policy); err != nil {
		return RetentionRecord{}, err
	}
	record := RetentionRecord{ProjectID: strings.TrimSpace(input.ProjectID), PolicyVersion: input.Policy.PolicyVersion, PolicyFingerprint: input.Policy.Fingerprint, SubjectReference: strings.TrimSpace(input.SubjectReference), CreatedAt: input.CreatedAt.UTC(), RetainUntil: input.RetainUntil.UTC(), Hold: input.Hold}
	if record.ProjectID != input.Policy.ProjectID {
		return RetentionRecord{}, ErrProjectMismatch
	}
	if !validSafeReference(record.SubjectReference) || record.CreatedAt.IsZero() || !record.RetainUntil.After(record.CreatedAt) {
		return RetentionRecord{}, ErrRetentionViolation
	}
	record.Fingerprint = retentionFingerprint(record)
	return record, nil
}

func ValidateRetentionRecord(record RetentionRecord) error {
	if !validSafeIdentifier(record.ProjectID) || !validSafeReference(record.SubjectReference) || !validSafeIdentifier(record.PolicyVersion) || !validFingerprint(record.PolicyFingerprint) || record.CreatedAt.IsZero() || !record.RetainUntil.After(record.CreatedAt) || !validFingerprint(record.Fingerprint) || record.Fingerprint != retentionFingerprint(record) {
		return ErrGovernanceIntegrityFailure
	}
	return nil
}

func EvaluateRetention(record RetentionRecord, now time.Time) (RetentionStatus, error) {
	if err := ValidateRetentionRecord(record); err != nil {
		return "", err
	}
	if now.UTC().IsZero() {
		return "", ErrRetentionViolation
	}
	if record.Hold {
		return RetentionHeld, nil
	}
	if !record.RetainUntil.After(now.UTC()) {
		return RetentionDeletionEligible, nil
	}
	return RetentionActive, nil
}

func findRule(rules []Rule, consumer Consumer) (Rule, bool) {
	for _, rule := range rules {
		if rule.Consumer == consumer {
			return rule, true
		}
	}
	return Rule{}, false
}

func decide(rule Rule, input EvaluationInput) (DecisionAction, string) {
	classificationRank := rank(input.Classification)
	maximumRank := rank(rule.Maximum)
	if input.Classification == dataclassification.LevelSecret {
		return DecisionDeny, "secret_representation_denied"
	}
	if classificationRank > maximumRank {
		if input.Consumer == ConsumerExecutiveReport && input.Classification == dataclassification.LevelRestricted {
			return DecisionAllowMetadataOnly, "consumer_classification_restricted"
		}
		if input.Classification == dataclassification.LevelSensitive {
			return DecisionAllowRedacted, "consumer_classification_redacted"
		}
		return DecisionDeny, "consumer_classification_denied"
	}
	if input.Classification == dataclassification.LevelRestricted {
		return DecisionAllowMetadataOnly, "restricted_metadata_only"
	}
	if input.Classification == dataclassification.LevelSensitive {
		return DecisionAllowRedacted, "sensitive_redaction_required"
	}
	return DecisionAllow, "classification_allowed"
}

func rank(level dataclassification.Level) int {
	switch level {
	case dataclassification.LevelPublic:
		return 0
	case dataclassification.LevelInternal:
		return 1
	case dataclassification.LevelSensitive:
		return 2
	case dataclassification.LevelRestricted:
		return 3
	case dataclassification.LevelSecret:
		return 4
	default:
		return -1
	}
}

func validRule(rule Rule) bool {
	return validConsumer(rule.Consumer) && rank(rule.Maximum) >= 0 && rule.Retention > 0 && rule.Retention <= 366*24*time.Hour
}

func validConsumer(value Consumer) bool {
	switch value {
	case ConsumerLocalStorage, ConsumerTechnicalReport, ConsumerExecutiveReport, ConsumerCLIOutput, ConsumerJSONExport, ConsumerMarkdownExport, ConsumerHTMLExport, ConsumerAuditLog, ConsumerAnalytics, ConsumerEgress:
		return true
	default:
		return false
	}
}

func validSubject(value Subject) bool {
	switch value {
	case SubjectTarget, SubjectHostname, SubjectIPAddress, SubjectURL, SubjectEndpoint, SubjectParameter, SubjectRequestMeta, SubjectResponseMeta, SubjectFinding, SubjectObservation, SubjectEvidence, SubjectValidation, SubjectCampaign, SubjectCampaignTask, SubjectTaskResult, SubjectRiskScore, SubjectReport, SubjectAuthorization, SubjectScope, SubjectAuditEvent, SubjectSnapshot, SubjectAnalytics, SubjectRegression, SubjectDecision:
		return true
	default:
		return false
	}
}

func validDecisionAction(value DecisionAction) bool {
	switch value {
	case DecisionAllow, DecisionAllowRedacted, DecisionAllowHashed, DecisionAllowMetadataOnly, DecisionDeny, DecisionExpire, DecisionDelete:
		return true
	default:
		return false
	}
}

func validSafeIdentifier(value string) bool {
	return dataclassification.ValidateSafeText(value, 256) == nil
}
func validSafeReference(value string) bool {
	return dataclassification.ValidateSafeReference(value) == nil
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func policyFingerprint(policy Policy) string {
	type canonicalRule struct {
		Consumer  Consumer                 `json:"consumer"`
		Maximum   dataclassification.Level `json:"maximum"`
		Retention int64                    `json:"retention_ns"`
	}
	rules := make([]canonicalRule, len(policy.Rules))
	for index, rule := range policy.Rules {
		rules[index] = canonicalRule{Consumer: rule.Consumer, Maximum: rule.Maximum, Retention: int64(rule.Retention)}
	}
	encoded, _ := json.Marshal(struct {
		ProjectID, Version, PolicyVersion string
		Rules                             []canonicalRule
		CreatedAt, ExpiresAt              time.Time
	}{policy.ProjectID, policy.Version, policy.PolicyVersion, rules, policy.CreatedAt.UTC(), policy.ExpiresAt.UTC()})
	return sha256Fingerprint(encoded)
}

func decisionFingerprint(decision Decision) string {
	encoded, _ := json.Marshal(struct {
		Action                                       DecisionAction
		ReasonCode, PolicyVersion, PolicyFingerprint string
		Classification                               dataclassification.Level
		Subject                                      Subject
		Consumer                                     Consumer
		ProjectID                                    string
		OccurredAt                                   time.Time
	}{decision.Action, decision.ReasonCode, decision.PolicyVersion, decision.PolicyFingerprint, decision.Classification, decision.Subject, decision.Consumer, decision.ProjectID, decision.OccurredAt.UTC()})
	return sha256Fingerprint(encoded)
}

func retentionFingerprint(record RetentionRecord) string {
	encoded, _ := json.Marshal(struct {
		ProjectID, PolicyVersion, PolicyFingerprint, SubjectReference string
		CreatedAt, RetainUntil                                        time.Time
		Hold                                                          bool
	}{record.ProjectID, record.PolicyVersion, record.PolicyFingerprint, record.SubjectReference, record.CreatedAt.UTC(), record.RetainUntil.UTC(), record.Hold})
	return sha256Fingerprint(encoded)
}

func sha256Fingerprint(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
