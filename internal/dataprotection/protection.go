// Package dataprotection is the pure T8 authority for safe data descriptors,
// closed protection profiles, and T7-governance-bound protection decisions.
package dataprotection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
)

var (
	ErrClassificationInvalid = errors.New("data classification is invalid")
	ErrProfileInvalid        = errors.New("data protection profile is invalid")
	ErrDescriptorInvalid     = errors.New("data descriptor is invalid")
	ErrGovernanceUnavailable = errors.New("data governance is unavailable")
	ErrGovernanceDenied      = errors.New("data governance denied protection")
	ErrProjectMismatch       = errors.New("data protection project mismatch")
	ErrDecisionDenied        = errors.New("data protection denied")
	ErrIntegrityFailure      = errors.New("data protection integrity validation failed")
	ErrDescriptorExpired     = errors.New("data descriptor is expired")
)

const Version = "t8.protection.v1"

type ObjectType string

const (
	ObjectEvidence   ObjectType = "evidence"
	ObjectFinding    ObjectType = "finding"
	ObjectReport     ObjectType = "report"
	ObjectSnapshot   ObjectType = "snapshot"
	ObjectAnalytics  ObjectType = "analytics"
	ObjectGovernance ObjectType = "governance"
	ObjectCampaign   ObjectType = "campaign"
	ObjectAuditEvent ObjectType = "audit_event"
	ObjectExport     ObjectType = "export"
)

type ProfileName string

const (
	ProfilePublicOutput     ProfileName = "public-output"
	ProfileInternalOutput   ProfileName = "internal-output"
	ProfileTechnicalOutput  ProfileName = "technical-output"
	ProfileExecutiveOutput  ProfileName = "executive-output"
	ProfileAuditEvent       ProfileName = "audit-event"
	ProfileLocalPersistence ProfileName = "local-persistence"
	ProfileExport           ProfileName = "export"
)

type FieldClass string

const (
	FieldSummary           FieldClass = "summary"
	FieldIdentifier        FieldClass = "identifier"
	FieldTargetReference   FieldClass = "target_reference"
	FieldEvidenceReference FieldClass = "evidence_reference"
	FieldClassification    FieldClass = "classification"
	FieldLineage           FieldClass = "lineage"
	FieldTimestamp         FieldClass = "timestamp"
	FieldAggregate         FieldClass = "aggregate"
)

type Action string

const (
	ActionAllow        Action = "allow"
	ActionRedact       Action = "redact"
	ActionMetadataOnly Action = "metadata_only"
	ActionDeny         Action = "deny"
)

type Profile struct {
	Name              ProfileName
	Version           string
	Consumer          datagovernance.Consumer
	Maximum           dataclassification.Level
	RedactionRequired bool
	Persistence       bool
	MayLeaveProcess   bool
	AllowedFields     []FieldClass
}

type DescriptorInput struct {
	ProjectID                   string
	ObjectType                  ObjectType
	ObjectID                    string
	Classification              dataclassification.Level
	SourceReference             string
	ScopeReference              string
	GovernancePolicyFingerprint string
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
}

type Descriptor struct {
	ProjectID                   string                   `json:"project_id"`
	ObjectType                  ObjectType               `json:"object_type"`
	ObjectID                    string                   `json:"object_id"`
	Classification              dataclassification.Level `json:"classification"`
	SourceReference             string                   `json:"source_reference"`
	ScopeReference              string                   `json:"scope_reference"`
	GovernancePolicyFingerprint string                   `json:"governance_policy_fingerprint"`
	Version                     string                   `json:"version"`
	CreatedAt                   time.Time                `json:"created_at"`
	ExpiresAt                   time.Time                `json:"expires_at,omitempty"`
	Fingerprint                 string                   `json:"fingerprint"`
}

type EvaluationInput struct {
	Descriptor         Descriptor
	Profile            ProfileName
	Policy             datagovernance.Policy
	GovernanceDecision datagovernance.Decision
	OccurredAt         time.Time
}

type Decision struct {
	ProjectID                     string                   `json:"project_id"`
	DescriptorFingerprint         string                   `json:"descriptor_fingerprint"`
	Profile                       ProfileName              `json:"profile"`
	ProfileVersion                string                   `json:"profile_version"`
	Action                        Action                   `json:"action"`
	ReasonCode                    string                   `json:"reason_code"`
	EffectiveClassification       dataclassification.Level `json:"effective_classification"`
	RedactionRequired             bool                     `json:"redaction_required"`
	AllowedFields                 []FieldClass             `json:"allowed_fields"`
	GovernancePolicyFingerprint   string                   `json:"governance_policy_fingerprint"`
	GovernanceDecisionFingerprint string                   `json:"governance_decision_fingerprint"`
	OccurredAt                    time.Time                `json:"occurred_at"`
	Fingerprint                   string                   `json:"fingerprint"`
}

func AggregateClassification(levels ...dataclassification.Level) (dataclassification.Level, error) {
	if len(levels) == 0 || len(levels) > 64 {
		return "", ErrClassificationInvalid
	}
	maximum := -1
	result := dataclassification.LevelPublic
	for _, level := range levels {
		rank, ok := classificationRank(level)
		if !ok {
			return "", ErrClassificationInvalid
		}
		if rank > maximum {
			maximum, result = rank, level
		}
	}
	return result, nil
}

func ProtectionProfile(name ProfileName) (Profile, error) {
	profiles := map[ProfileName]Profile{
		ProfilePublicOutput:     {Name: ProfilePublicOutput, Version: Version, Consumer: datagovernance.ConsumerCLIOutput, Maximum: dataclassification.LevelPublic, AllowedFields: []FieldClass{FieldSummary, FieldAggregate, FieldClassification, FieldTimestamp}},
		ProfileInternalOutput:   {Name: ProfileInternalOutput, Version: Version, Consumer: datagovernance.ConsumerCLIOutput, Maximum: dataclassification.LevelInternal, AllowedFields: []FieldClass{FieldSummary, FieldIdentifier, FieldClassification, FieldTimestamp}},
		ProfileTechnicalOutput:  {Name: ProfileTechnicalOutput, Version: Version, Consumer: datagovernance.ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, AllowedFields: []FieldClass{FieldSummary, FieldIdentifier, FieldTargetReference, FieldEvidenceReference, FieldClassification, FieldLineage, FieldTimestamp}},
		ProfileExecutiveOutput:  {Name: ProfileExecutiveOutput, Version: Version, Consumer: datagovernance.ConsumerExecutiveReport, Maximum: dataclassification.LevelInternal, RedactionRequired: true, AllowedFields: []FieldClass{FieldSummary, FieldAggregate, FieldClassification, FieldTimestamp}},
		ProfileAuditEvent:       {Name: ProfileAuditEvent, Version: Version, Consumer: datagovernance.ConsumerAuditLog, Maximum: dataclassification.LevelInternal, RedactionRequired: true, Persistence: true, AllowedFields: []FieldClass{FieldIdentifier, FieldEvidenceReference, FieldClassification, FieldTimestamp}},
		ProfileLocalPersistence: {Name: ProfileLocalPersistence, Version: Version, Consumer: datagovernance.ConsumerLocalStorage, Maximum: dataclassification.LevelSensitive, Persistence: true, AllowedFields: []FieldClass{FieldIdentifier, FieldTargetReference, FieldEvidenceReference, FieldClassification, FieldLineage, FieldTimestamp}},
		ProfileExport:           {Name: ProfileExport, Version: Version, Consumer: datagovernance.ConsumerJSONExport, Maximum: dataclassification.LevelInternal, RedactionRequired: true, MayLeaveProcess: true, AllowedFields: []FieldClass{FieldSummary, FieldIdentifier, FieldClassification, FieldTimestamp}},
	}
	profile, exists := profiles[name]
	if !exists {
		return Profile{}, ErrProfileInvalid
	}
	profile.AllowedFields = append([]FieldClass(nil), profile.AllowedFields...)
	return profile, nil
}

func NewDescriptor(input DescriptorInput) (Descriptor, error) {
	descriptor := Descriptor{ProjectID: strings.TrimSpace(input.ProjectID), ObjectType: input.ObjectType, ObjectID: strings.TrimSpace(input.ObjectID), Classification: input.Classification, SourceReference: strings.TrimSpace(input.SourceReference), ScopeReference: strings.TrimSpace(input.ScopeReference), GovernancePolicyFingerprint: strings.TrimSpace(input.GovernancePolicyFingerprint), Version: Version, CreatedAt: input.CreatedAt.UTC(), ExpiresAt: input.ExpiresAt.UTC()}
	if !validDescriptorFields(descriptor) {
		return Descriptor{}, ErrDescriptorInvalid
	}
	descriptor.Fingerprint = descriptorFingerprint(descriptor)
	return descriptor, nil
}

func ValidateDescriptor(descriptor Descriptor) error {
	canonical, err := NewDescriptor(DescriptorInput{ProjectID: descriptor.ProjectID, ObjectType: descriptor.ObjectType, ObjectID: descriptor.ObjectID, Classification: descriptor.Classification, SourceReference: descriptor.SourceReference, ScopeReference: descriptor.ScopeReference, GovernancePolicyFingerprint: descriptor.GovernancePolicyFingerprint, CreatedAt: descriptor.CreatedAt, ExpiresAt: descriptor.ExpiresAt})
	if err != nil || descriptor.Version != Version || descriptor.Fingerprint != canonical.Fingerprint {
		return ErrIntegrityFailure
	}
	return nil
}

func Evaluate(input EvaluationInput) (Decision, error) {
	if err := ValidateDescriptor(input.Descriptor); err != nil {
		return Decision{}, err
	}
	if input.OccurredAt.UTC().IsZero() {
		return Decision{}, ErrDescriptorInvalid
	}
	if !input.Descriptor.ExpiresAt.IsZero() && !input.Descriptor.ExpiresAt.After(input.OccurredAt.UTC()) {
		return Decision{}, ErrDescriptorExpired
	}
	profile, err := ProtectionProfile(input.Profile)
	if err != nil {
		return Decision{}, err
	}
	if err := datagovernance.ValidatePolicy(input.Policy); err != nil {
		return Decision{}, ErrGovernanceUnavailable
	}
	if input.Policy.ProjectID != input.Descriptor.ProjectID || input.Policy.Fingerprint != input.Descriptor.GovernancePolicyFingerprint {
		return Decision{}, ErrProjectMismatch
	}
	if err := datagovernance.ValidateDecision(input.GovernanceDecision); err != nil {
		return Decision{}, ErrGovernanceUnavailable
	}
	if input.GovernanceDecision.ProjectID != input.Descriptor.ProjectID || input.GovernanceDecision.PolicyFingerprint != input.Policy.Fingerprint || input.GovernanceDecision.Classification != input.Descriptor.Classification || input.GovernanceDecision.Consumer != profile.Consumer || input.GovernanceDecision.Subject != governanceSubject(input.Descriptor.ObjectType) {
		return Decision{}, ErrGovernanceUnavailable
	}
	canonicalGovernance, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: input.Policy, ProjectID: input.Descriptor.ProjectID, Subject: governanceSubject(input.Descriptor.ObjectType), Classification: input.Descriptor.Classification, Consumer: profile.Consumer, OccurredAt: input.OccurredAt.UTC()})
	if err != nil || canonicalGovernance.Fingerprint != input.GovernanceDecision.Fingerprint {
		return Decision{}, ErrGovernanceUnavailable
	}
	decision := Decision{ProjectID: input.Descriptor.ProjectID, DescriptorFingerprint: input.Descriptor.Fingerprint, Profile: profile.Name, ProfileVersion: profile.Version, EffectiveClassification: input.Descriptor.Classification, RedactionRequired: profile.RedactionRequired, AllowedFields: append([]FieldClass(nil), profile.AllowedFields...), GovernancePolicyFingerprint: input.Policy.Fingerprint, GovernanceDecisionFingerprint: input.GovernanceDecision.Fingerprint, OccurredAt: input.OccurredAt.UTC()}
	switch canonicalGovernance.Action {
	case datagovernance.DecisionDeny:
		decision.Action, decision.ReasonCode = ActionDeny, "governance_denied"
	case datagovernance.DecisionAllowMetadataOnly:
		decision.Action, decision.ReasonCode, decision.RedactionRequired = ActionMetadataOnly, "profile_restricted_metadata_only", true
		decision.AllowedFields = []FieldClass{FieldSummary, FieldClassification, FieldTimestamp}
	case datagovernance.DecisionAllowRedacted:
		decision.Action, decision.ReasonCode, decision.RedactionRequired = ActionRedact, "governance_redaction_required", true
	default:
		if input.Descriptor.Classification == dataclassification.LevelSecret {
			decision.Action, decision.ReasonCode, decision.RedactionRequired = ActionDeny, "secret_representation_denied", true
		} else if profile.RedactionRequired {
			decision.Action, decision.ReasonCode = ActionRedact, "profile_redaction_required"
		} else {
			decision.Action, decision.ReasonCode = ActionAllow, "protection_allowed"
		}
	}
	decision.Fingerprint = decisionFingerprint(decision)
	return decision, nil
}

func ValidateDecision(decision Decision) error {
	profile, err := ProtectionProfile(decision.Profile)
	if err != nil || decision.ProfileVersion != Version || decision.ProjectID == "" || !validFingerprint(decision.DescriptorFingerprint) || !validFingerprint(decision.GovernancePolicyFingerprint) || !validFingerprint(decision.GovernanceDecisionFingerprint) || !validAction(decision.Action) || !validSafeReason(decision.ReasonCode) || !dataclassification.ValidLevel(string(decision.EffectiveClassification)) || decision.OccurredAt.UTC().IsZero() || !validFingerprint(decision.Fingerprint) || !sameFields(profile, decision) || decision.Fingerprint != decisionFingerprint(decision) {
		return ErrIntegrityFailure
	}
	return nil
}

func Redact(value string) (string, error) {
	if value == dataclassification.RedactedValue {
		return value, nil
	}
	if len(value) > dataclassification.DefaultLimits().MaxStringBytes || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrDescriptorInvalid
	}
	decision, err := dataclassification.Classify(dataclassification.Input{Kind: dataclassification.KindGeneric, Name: "value", Value: value, Destination: dataclassification.DestinationReport})
	if err != nil {
		return "", err
	}
	return decision.Value, nil
}

func validDescriptorFields(descriptor Descriptor) bool {
	_, classificationOK := classificationRank(descriptor.Classification)
	return validObjectType(descriptor.ObjectType) && dataclassification.ValidateSafeText(descriptor.ProjectID, 256) == nil && dataclassification.ValidateSafeReference(descriptor.ObjectID) == nil && classificationOK && dataclassification.ValidateSafeReference(descriptor.SourceReference) == nil && dataclassification.ValidateSafeReference(descriptor.ScopeReference) == nil && validFingerprint(descriptor.GovernancePolicyFingerprint) && !descriptor.CreatedAt.IsZero() && (descriptor.ExpiresAt.IsZero() || descriptor.ExpiresAt.After(descriptor.CreatedAt))
}

func validObjectType(value ObjectType) bool {
	switch value {
	case ObjectEvidence, ObjectFinding, ObjectReport, ObjectSnapshot, ObjectAnalytics, ObjectGovernance, ObjectCampaign, ObjectAuditEvent, ObjectExport:
		return true
	default:
		return false
	}
}

func governanceSubject(objectType ObjectType) datagovernance.Subject {
	switch objectType {
	case ObjectEvidence:
		return datagovernance.SubjectEvidence
	case ObjectFinding:
		return datagovernance.SubjectFinding
	case ObjectReport:
		return datagovernance.SubjectReport
	case ObjectSnapshot:
		return datagovernance.SubjectSnapshot
	case ObjectAnalytics:
		return datagovernance.SubjectAnalytics
	case ObjectGovernance:
		return datagovernance.SubjectDecision
	case ObjectCampaign:
		return datagovernance.SubjectCampaign
	case ObjectAuditEvent:
		return datagovernance.SubjectAuditEvent
	case ObjectExport:
		return datagovernance.SubjectReport
	default:
		return ""
	}
}

// GovernanceSubjectForObject returns the closed T7 subject mapping for a
// supported T8 object type. It never permits caller-defined subject values.
func GovernanceSubjectForObject(objectType ObjectType) (datagovernance.Subject, error) {
	if !validObjectType(objectType) {
		return "", ErrDescriptorInvalid
	}
	return governanceSubject(objectType), nil
}

func classificationRank(level dataclassification.Level) (int, bool) {
	switch level {
	case dataclassification.LevelPublic:
		return 0, true
	case dataclassification.LevelInternal:
		return 1, true
	case dataclassification.LevelSensitive:
		return 2, true
	case dataclassification.LevelRestricted:
		return 3, true
	case dataclassification.LevelSecret:
		return 4, true
	default:
		return -1, false
	}
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validAction(value Action) bool {
	return value == ActionAllow || value == ActionRedact || value == ActionMetadataOnly || value == ActionDeny
}
func validSafeReason(value string) bool {
	return dataclassification.ValidateSafeText(value, 128) == nil
}

func sameFields(profile Profile, decision Decision) bool {
	fields := append([]FieldClass(nil), decision.AllowedFields...)
	if decision.Action == ActionMetadataOnly {
		return equalFields(fields, []FieldClass{FieldSummary, FieldClassification, FieldTimestamp})
	}
	return equalFields(fields, profile.AllowedFields)
}

func equalFields(left, right []FieldClass) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func descriptorFingerprint(descriptor Descriptor) string {
	encoded, _ := json.Marshal(struct {
		ProjectID                                                             string
		ObjectType                                                            ObjectType
		ObjectID                                                              string
		Classification                                                        dataclassification.Level
		SourceReference, ScopeReference, GovernancePolicyFingerprint, Version string
		CreatedAt, ExpiresAt                                                  time.Time
	}{descriptor.ProjectID, descriptor.ObjectType, descriptor.ObjectID, descriptor.Classification, descriptor.SourceReference, descriptor.ScopeReference, descriptor.GovernancePolicyFingerprint, descriptor.Version, descriptor.CreatedAt.UTC(), descriptor.ExpiresAt.UTC()})
	return fingerprint(encoded)
}

func decisionFingerprint(decision Decision) string {
	fields := append([]FieldClass(nil), decision.AllowedFields...)
	sort.Slice(fields, func(left, right int) bool { return fields[left] < fields[right] })
	encoded, _ := json.Marshal(struct {
		ProjectID, DescriptorFingerprint                           string
		Profile                                                    ProfileName
		ProfileVersion                                             string
		Action                                                     Action
		ReasonCode                                                 string
		EffectiveClassification                                    dataclassification.Level
		RedactionRequired                                          bool
		AllowedFields                                              []FieldClass
		GovernancePolicyFingerprint, GovernanceDecisionFingerprint string
		OccurredAt                                                 time.Time
	}{decision.ProjectID, decision.DescriptorFingerprint, decision.Profile, decision.ProfileVersion, decision.Action, decision.ReasonCode, decision.EffectiveClassification, decision.RedactionRequired, fields, decision.GovernancePolicyFingerprint, decision.GovernanceDecisionFingerprint, decision.OccurredAt.UTC()})
	return fingerprint(encoded)
}

func fingerprint(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

// Snapshot is an immutable, secret-free record of a protection decision. It
// stores only canonical metadata and fingerprints; it never stores a raw value.
type SnapshotInput struct {
	ProjectID  string
	SnapshotID string
	Descriptor Descriptor
	Decision   Decision
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

type Snapshot struct {
	ProjectID             string                   `json:"project_id"`
	SnapshotID            string                   `json:"snapshot_id"`
	DescriptorFingerprint string                   `json:"descriptor_fingerprint"`
	DecisionFingerprint   string                   `json:"decision_fingerprint"`
	Profile               ProfileName              `json:"profile"`
	Classification        dataclassification.Level `json:"classification"`
	Version               string                   `json:"version"`
	CreatedAt             time.Time                `json:"created_at"`
	ExpiresAt             time.Time                `json:"expires_at,omitempty"`
	Fingerprint           string                   `json:"fingerprint"`
}

func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	if err := ValidateDescriptor(input.Descriptor); err != nil {
		return Snapshot{}, err
	}
	if err := ValidateDecision(input.Decision); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{ProjectID: strings.TrimSpace(input.ProjectID), SnapshotID: strings.TrimSpace(input.SnapshotID), DescriptorFingerprint: input.Descriptor.Fingerprint, DecisionFingerprint: input.Decision.Fingerprint, Profile: input.Decision.Profile, Classification: input.Decision.EffectiveClassification, Version: Version, CreatedAt: input.CreatedAt.UTC(), ExpiresAt: input.ExpiresAt.UTC()}
	if snapshot.ProjectID != input.Descriptor.ProjectID || snapshot.ProjectID != input.Decision.ProjectID || snapshot.Classification != input.Descriptor.Classification || dataclassification.ValidateSafeText(snapshot.ProjectID, 256) != nil || dataclassification.ValidateSafeReference(snapshot.SnapshotID) != nil || !validFingerprint(snapshot.DescriptorFingerprint) || !validFingerprint(snapshot.DecisionFingerprint) || !dataclassification.ValidLevel(string(snapshot.Classification)) || snapshot.CreatedAt.IsZero() || (!snapshot.ExpiresAt.IsZero() && !snapshot.ExpiresAt.After(snapshot.CreatedAt)) {
		return Snapshot{}, ErrDescriptorInvalid
	}
	if _, err := ProtectionProfile(snapshot.Profile); err != nil {
		return Snapshot{}, err
	}
	snapshot.Fingerprint = snapshotFingerprint(snapshot)
	return snapshot, nil
}

func ValidateSnapshot(snapshot Snapshot) error {
	if dataclassification.ValidateSafeText(snapshot.ProjectID, 256) != nil || dataclassification.ValidateSafeReference(snapshot.SnapshotID) != nil || !validFingerprint(snapshot.DescriptorFingerprint) || !validFingerprint(snapshot.DecisionFingerprint) || !dataclassification.ValidLevel(string(snapshot.Classification)) || snapshot.Version != Version || snapshot.CreatedAt.UTC().IsZero() || (!snapshot.ExpiresAt.IsZero() && !snapshot.ExpiresAt.After(snapshot.CreatedAt)) || !validFingerprint(snapshot.Fingerprint) {
		return ErrIntegrityFailure
	}
	if _, err := ProtectionProfile(snapshot.Profile); err != nil || snapshot.Fingerprint != snapshotFingerprint(snapshot) {
		return ErrIntegrityFailure
	}
	return nil
}

func snapshotFingerprint(snapshot Snapshot) string {
	encoded, _ := json.Marshal(struct {
		ProjectID, SnapshotID, DescriptorFingerprint, DecisionFingerprint string
		Profile                                                           ProfileName
		Classification                                                    dataclassification.Level
		Version                                                           string
		CreatedAt, ExpiresAt                                              time.Time
	}{snapshot.ProjectID, snapshot.SnapshotID, snapshot.DescriptorFingerprint, snapshot.DecisionFingerprint, snapshot.Profile, snapshot.Classification, snapshot.Version, snapshot.CreatedAt.UTC(), snapshot.ExpiresAt.UTC()})
	return fingerprint(encoded)
}
