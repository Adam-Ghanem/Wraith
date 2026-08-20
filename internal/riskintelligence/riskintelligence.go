// Package riskintelligence converts validated R11.4/R9 inputs into local,
// deterministic, project-scoped findings. It intentionally has no network,
// transport, DNS, subprocess, scanner, validation, or correlation behavior.
package riskintelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/findingvalidation"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

const RiskModelVersion = "r11.5-v1"

type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

type RiskBand string

const (
	BandInformational RiskBand = "informational"
	BandLow           RiskBand = "low"
	BandMedium        RiskBand = "medium"
	BandHigh          RiskBand = "high"
	BandCritical      RiskBand = "critical"
)

type Status string

const (
	StatusOpen          Status = "open"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
	StatusResolved      Status = "resolved"
	StatusReopened      Status = "reopened"
	StatusSuppressed    Status = "suppressed"
)

type AssetCriticality string

const (
	CriticalityUnknown  AssetCriticality = "unknown"
	CriticalityLow      AssetCriticality = "low"
	CriticalityMedium   AssetCriticality = "medium"
	CriticalityHigh     AssetCriticality = "high"
	CriticalityCritical AssetCriticality = "critical"
)

type Exposure string

const (
	ExposureUnknown        Exposure = "unknown"
	ExposureInternetFacing Exposure = "internet_facing"
	ExposureInternal       Exposure = "internal"
)

type Authentication string

const (
	AuthenticationUnknown         Authentication = "unknown"
	AuthenticationUnauthenticated Authentication = "unauthenticated"
	AuthenticationAuthenticated   Authentication = "authenticated"
	AuthenticationPrivileged      Authentication = "privileged"
)

type DataSensitivity string

const (
	SensitivityUnknown      DataSensitivity = "unknown"
	SensitivityPublic       DataSensitivity = "public"
	SensitivityInternal     DataSensitivity = "internal"
	SensitivityConfidential DataSensitivity = "confidential"
	SensitivityRestricted   DataSensitivity = "restricted"
)

type Exploitability string

const (
	ExploitabilityNone               Exploitability = "none"
	ExploitabilitySuspected          Exploitability = "suspected"
	ExploitabilityDemonstrated       Exploitability = "demonstrated"
	ExploitabilityHighlyReproducible Exploitability = "highly_reproducible"
)

type RiskContext struct {
	AssetID          string
	AssetCriticality AssetCriticality
	Exposure         Exposure
	Authentication   Authentication
	DataSensitivity  DataSensitivity
	Exploitability   Exploitability
}

type RiskFactor struct {
	Name, Reason  string
	Value, Weight int
}

type RiskAssessment struct {
	Score        int          `json:"score"`
	Band         RiskBand     `json:"band"`
	Factors      []RiskFactor `json:"factors"`
	Reason       string       `json:"reason"`
	Version      string       `json:"version"`
	CalculatedAt time.Time    `json:"calculated_at"`
}

type SecurityFinding struct {
	FindingID, ProjectID, RunID, ValidationID, CorrelationID string
	EndpointID, ParameterID, AssetID, Fingerprint            string
	Class                                                    injection.InjectionClass
	Subtype, Title, Description, RemediationHint             string
	Confidence                                               findingvalidation.Confidence
	Severity                                                 Severity
	Risk                                                     RiskAssessment
	Status                                                   Status
	FirstSeenAt, LastSeenAt, ValidatedAt                     time.Time
	EvidenceReferences                                       []string
}

type AssessmentInput struct {
	Candidate     findingvalidation.FindingCandidate
	Validation    findingvalidation.ValidationResult
	CorrelationID string
	Context       RiskContext
	ObservedAt    time.Time
}

type Assessment struct {
	Finding SecurityFinding
	Risk    RiskAssessment
}

func AssessFinding(input AssessmentInput) (Assessment, error) {
	if !validAssessmentInput(input) {
		return Assessment{}, errors.New("invalid risk assessment input")
	}
	context := normalizeContext(input.Context)
	severity := severityFromHint(input.Candidate.SeverityHint)
	fingerprint := findingFingerprint(input.Candidate, context)
	risk := CalculateRisk(severity, input.Validation.Confidence, input.Validation.Repeatability, context, input.ObservedAt)
	seen := input.ObservedAt.UTC()
	finding := SecurityFinding{FindingID: fingerprint, ProjectID: input.Candidate.ProjectID, RunID: input.Candidate.RunID, ValidationID: input.Candidate.ValidationID, CorrelationID: strings.TrimSpace(input.CorrelationID), EndpointID: input.Candidate.EndpointID, ParameterID: input.Candidate.ParameterID, AssetID: context.AssetID, Class: input.Candidate.Class, Subtype: "validated_" + string(input.Candidate.Class), Title: "Validated injection behavior requires remediation review", Description: "Validated, repeatable structural behavior was correlated from redacted evidence. Impact and priority are limited to the recorded validation context.", RemediationHint: remediationHint(input.Candidate.Class), Confidence: input.Validation.Confidence, Severity: severity, Risk: risk, Status: StatusOpen, FirstSeenAt: seen, LastSeenAt: seen, ValidatedAt: seen, Fingerprint: fingerprint, EvidenceReferences: uniqueReferences(input.Candidate.EvidenceRefs)}
	return Assessment{Finding: finding, Risk: risk}, nil
}

func CalculateRisk(severity Severity, confidence findingvalidation.Confidence, repeatability findingvalidation.Repeatability, context RiskContext, calculatedAt time.Time) RiskAssessment {
	context = normalizeContext(context)
	factors := []RiskFactor{
		{"severity", string(severity), severityWeight(severity), severityWeight(severity)},
		{"confidence", string(confidence), confidenceWeight(confidence), confidenceWeight(confidence)},
		{"repeatability", string(repeatability), repeatabilityWeight(repeatability), repeatabilityWeight(repeatability)},
		{"exposure", string(context.Exposure), exposureWeight(context.Exposure), exposureWeight(context.Exposure)},
		{"asset_criticality", string(context.AssetCriticality), criticalityWeight(context.AssetCriticality), criticalityWeight(context.AssetCriticality)},
		{"authentication", string(context.Authentication), authenticationWeight(context.Authentication), authenticationWeight(context.Authentication)},
		{"data_sensitivity", string(context.DataSensitivity), sensitivityWeight(context.DataSensitivity), sensitivityWeight(context.DataSensitivity)},
		{"exploitability", string(context.Exploitability), exploitabilityWeight(context.Exploitability), exploitabilityWeight(context.Exploitability)},
	}
	score := 0
	for index := range factors {
		score += factors[index].Weight
		factors[index].Reason = factors[index].Name + "=" + factors[index].Reason
	}
	if score > 100 {
		score = 100
	}
	return RiskAssessment{Score: score, Band: riskBand(score), Factors: factors, Reason: "Deterministic score from validated evidence, severity, confidence, repeatability, and recorded context.", Version: RiskModelVersion, CalculatedAt: calculatedAt.UTC()}
}

type LifecycleInput struct {
	Reason, CreatedBy string
	At                time.Time
	ExpiresAt         time.Time
}

type FindingHistory struct {
	FindingID, ProjectID, Event, Reason, CreatedBy string
	At                                             time.Time
}

type Suppression struct {
	ProjectID, Fingerprint, Reason, CreatedBy string
	CreatedAt, ExpiresAt                      time.Time
}

func Transition(finding SecurityFinding, next Status, input LifecycleInput) (SecurityFinding, FindingHistory, error) {
	if finding.ProjectID == "" || finding.FindingID == "" || !validStatus(next) || input.At.IsZero() || (next == StatusAccepted && strings.TrimSpace(input.Reason) == "") || (next == StatusSuppressed && strings.TrimSpace(input.Reason) == "") || !allowedTransition(finding.Status, next) {
		return SecurityFinding{}, FindingHistory{}, errors.New("invalid finding lifecycle transition")
	}
	finding.Status, finding.LastSeenAt = next, input.At.UTC()
	return finding, FindingHistory{FindingID: finding.FindingID, ProjectID: finding.ProjectID, Event: string(next), Reason: strings.TrimSpace(input.Reason), CreatedBy: strings.TrimSpace(input.CreatedBy), At: input.At.UTC()}, nil
}

func ApplySuppression(finding SecurityFinding, suppression Suppression, now time.Time) (SecurityFinding, *FindingHistory, error) {
	if finding.ProjectID == "" || finding.Fingerprint == "" || suppression.ProjectID != finding.ProjectID || suppression.Fingerprint != finding.Fingerprint || strings.TrimSpace(suppression.Reason) == "" || suppression.CreatedAt.IsZero() || now.IsZero() {
		return SecurityFinding{}, nil, errors.New("invalid finding suppression")
	}
	if !suppression.ExpiresAt.IsZero() && !suppression.ExpiresAt.After(now) {
		return finding, nil, nil
	}
	updated, history, err := Transition(finding, StatusSuppressed, LifecycleInput{Reason: suppression.Reason, CreatedBy: suppression.CreatedBy, At: now, ExpiresAt: suppression.ExpiresAt})
	if err != nil {
		return SecurityFinding{}, nil, err
	}
	return updated, &history, nil
}

func PrioritizeFindings(findings []SecurityFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Risk.Score != findings[j].Risk.Score {
			return findings[i].Risk.Score > findings[j].Risk.Score
		}
		if severityWeight(findings[i].Severity) != severityWeight(findings[j].Severity) {
			return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
		}
		return findings[i].FindingID < findings[j].FindingID
	})
}

func (assessment Assessment) JSON() string {
	encoded, err := json.Marshal(assessment)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func validAssessmentInput(input AssessmentInput) bool {
	candidate, validation := input.Candidate, input.Validation
	return candidate.ProjectID != "" && candidate.Status == findingvalidation.FindingCandidateValidated && candidate.ValidationID != "" && validation.ValidationID == candidate.ValidationID && validation.Status == findingvalidation.StatusValidated && validation.Confidence == candidate.Confidence && validation.Repeatability == findingvalidation.Repeatable && candidate.EndpointID != "" && candidate.ParameterID != "" && candidate.Fingerprint != "" && input.CorrelationID != "" && !input.ObservedAt.IsZero() && validClass(candidate.Class) && len(uniqueReferences(candidate.EvidenceRefs)) > 0 && validSeverityHint(candidate.SeverityHint)
}

func normalizeContext(context RiskContext) RiskContext {
	if !validCriticality(context.AssetCriticality) {
		context.AssetCriticality = CriticalityUnknown
	}
	if !validExposure(context.Exposure) {
		context.Exposure = ExposureUnknown
	}
	if !validAuthentication(context.Authentication) {
		context.Authentication = AuthenticationUnknown
	}
	if !validSensitivity(context.DataSensitivity) {
		context.DataSensitivity = SensitivityUnknown
	}
	if !validExploitability(context.Exploitability) {
		context.Exploitability = ExploitabilityNone
	}
	context.AssetID = strings.TrimSpace(context.AssetID)
	return context
}

func findingFingerprint(candidate findingvalidation.FindingCandidate, context RiskContext) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{candidate.ProjectID, context.AssetID, candidate.EndpointID, candidate.ParameterID, string(candidate.Class), "validated_" + string(candidate.Class)}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func severityFromHint(value string) Severity { return Severity(value) }
func validSeverityHint(value string) bool {
	return value == string(SeverityInformational) || value == string(SeverityLow) || value == string(SeverityMedium) || value == string(SeverityHigh) || value == string(SeverityCritical)
}
func validClass(value injection.InjectionClass) bool {
	switch value {
	case injection.ClassSQL, injection.ClassNoSQL, injection.ClassCommand, injection.ClassSSTI, injection.ClassHPP, injection.ClassHeader, injection.ClassPath:
		return true
	}
	return false
}
func validStatus(value Status) bool {
	switch value {
	case StatusOpen, StatusAccepted, StatusFalsePositive, StatusResolved, StatusReopened, StatusSuppressed:
		return true
	}
	return false
}
func allowedTransition(current, next Status) bool {
	return map[Status]map[Status]bool{StatusOpen: {StatusAccepted: true, StatusResolved: true, StatusSuppressed: true, StatusFalsePositive: true}, StatusAccepted: {StatusResolved: true}, StatusResolved: {StatusReopened: true}, StatusFalsePositive: {StatusReopened: true}, StatusSuppressed: {StatusOpen: true}}[current][next]
}
func validCriticality(value AssetCriticality) bool {
	switch value {
	case CriticalityUnknown, CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return true
	}
	return false
}
func validExposure(value Exposure) bool {
	return value == ExposureUnknown || value == ExposureInternetFacing || value == ExposureInternal
}
func validAuthentication(value Authentication) bool {
	return value == AuthenticationUnknown || value == AuthenticationUnauthenticated || value == AuthenticationAuthenticated || value == AuthenticationPrivileged
}
func validSensitivity(value DataSensitivity) bool {
	return value == SensitivityUnknown || value == SensitivityPublic || value == SensitivityInternal || value == SensitivityConfidential || value == SensitivityRestricted
}
func validExploitability(value Exploitability) bool {
	return value == ExploitabilityNone || value == ExploitabilitySuspected || value == ExploitabilityDemonstrated || value == ExploitabilityHighlyReproducible
}
func severityWeight(value Severity) int {
	return map[Severity]int{SeverityInformational: 5, SeverityLow: 15, SeverityMedium: 30, SeverityHigh: 45, SeverityCritical: 60}[value]
}
func confidenceWeight(value findingvalidation.Confidence) int {
	return map[findingvalidation.Confidence]int{findingvalidation.ConfidenceLow: 2, findingvalidation.ConfidenceMedium: 6, findingvalidation.ConfidenceHigh: 10}[value]
}
func repeatabilityWeight(value findingvalidation.Repeatability) int {
	return map[findingvalidation.Repeatability]int{findingvalidation.NonRepeatable: 0, findingvalidation.PartiallyRepeatable: 4, findingvalidation.Repeatable: 8}[value]
}
func exposureWeight(value Exposure) int {
	return map[Exposure]int{ExposureUnknown: 0, ExposureInternal: 4, ExposureInternetFacing: 12}[value]
}
func criticalityWeight(value AssetCriticality) int {
	return map[AssetCriticality]int{CriticalityUnknown: 0, CriticalityLow: 2, CriticalityMedium: 5, CriticalityHigh: 8, CriticalityCritical: 12}[value]
}
func authenticationWeight(value Authentication) int {
	return map[Authentication]int{AuthenticationUnknown: 0, AuthenticationUnauthenticated: 6, AuthenticationAuthenticated: 2, AuthenticationPrivileged: 1}[value]
}
func sensitivityWeight(value DataSensitivity) int {
	return map[DataSensitivity]int{SensitivityUnknown: 0, SensitivityPublic: 1, SensitivityInternal: 3, SensitivityConfidential: 5, SensitivityRestricted: 8}[value]
}
func exploitabilityWeight(value Exploitability) int {
	return map[Exploitability]int{ExploitabilityNone: 0, ExploitabilitySuspected: 2, ExploitabilityDemonstrated: 6, ExploitabilityHighlyReproducible: 10}[value]
}
func riskBand(score int) RiskBand {
	switch {
	case score < 20:
		return BandInformational
	case score < 40:
		return BandLow
	case score < 60:
		return BandMedium
	case score < 80:
		return BandHigh
	default:
		return BandCritical
	}
}
func remediationHint(class injection.InjectionClass) string {
	switch class {
	case injection.ClassSQL, injection.ClassNoSQL:
		return "Use parameterized query interfaces and strict server-side input handling."
	case injection.ClassSSTI:
		return "Avoid evaluating untrusted template input and use safe template contexts."
	case injection.ClassCommand:
		return "Avoid shell interpretation; use fixed command arguments and allowlists."
	default:
		return "Apply strict server-side input validation and the least-privilege design appropriate to this interface."
	}
}
func uniqueReferences(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !sensitive(value) {
			seen[value] = true
		}
	}
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func sensitive(value string) bool {
	lower := strings.ToLower(value)
	for _, blocked := range []string{"password", "cookie", "authorization", "api_key", "apikey", "token", "secret", "bearer", "session="} {
		if strings.Contains(lower, blocked) {
			return true
		}
	}
	return false
}
