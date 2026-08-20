package findingvalidation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

type Repeatability string

const (
	NonRepeatable       Repeatability = "non_repeatable"
	PartiallyRepeatable Repeatability = "partially_repeatable"
	Repeatable          Repeatability = "repeatable"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ValidationResult struct {
	ValidationID, Fingerprint, StopReason string
	Status                                Status
	Confidence                            Confidence
	Repeatability                         Repeatability
	EvidenceQuality                       string
	ImpactSignal                          string
	RequestCount                          int
	EvidenceReferences                    []string
}

// Assess deterministically converts bounded structural repetitions into a
// validation result. It never creates a final finding or maps confidence to severity.
func Assess(candidate ValidationCandidate, diffs []ValidationDiff) ValidationResult {
	result := ValidationResult{ValidationID: candidate.ValidationID, Status: StatusRejected, Confidence: ConfidenceLow, Repeatability: NonRepeatable, EvidenceQuality: "insufficient", Fingerprint: candidate.Fingerprint}
	if candidate.ProjectID == "" || candidate.ValidationID == "" || len(diffs) == 0 {
		return result
	}
	security := 0
	fingerprints := map[string]int{}
	for _, diff := range diffs {
		if diff.SecurityRelevant {
			security++
			if strings.TrimSpace(diff.Fingerprint) != "" {
				fingerprints[diff.Fingerprint]++
			}
		}
	}
	if security == 0 {
		return result
	}
	result.Status, result.Confidence, result.EvidenceQuality = StatusInconclusive, ConfidenceMedium, "single bounded differential"
	result.Repeatability = PartiallyRepeatable
	for _, count := range fingerprints {
		if count >= 2 {
			result.Status, result.Confidence, result.Repeatability, result.EvidenceQuality = StatusValidated, ConfidenceHigh, Repeatable, "repeatable bounded differential"
			result.ImpactSignal = "validated structural response behavior"
			return result
		}
	}
	return result
}

type FindingCandidateStatus string

const (
	FindingCandidateValidated FindingCandidateStatus = "validated"
	FindingCandidateRejected  FindingCandidateStatus = "rejected"
)

// FindingCandidate is a transient R11.4-to-R9 handoff object, not R9's final finding model.
type FindingCandidate struct {
	FindingID, ProjectID, RunID, ValidationID, EndpointID, ParameterID, Fingerprint string
	Class                                                                           injection.InjectionClass
	Title, Description, SeverityHint                                                string
	Confidence                                                                      Confidence
	EvidenceRefs                                                                    []string
	Status                                                                          FindingCandidateStatus
}

func NewFindingCandidate(candidate ValidationCandidate, result ValidationResult, evidenceRefs []string) (FindingCandidate, error) {
	if candidate.ProjectID == "" || candidate.ValidationID == "" || candidate.EndpointID == "" || candidate.ParameterID == "" || result.ValidationID != candidate.ValidationID || result.Status != StatusValidated || result.Confidence == "" || !validClass(candidate.InjectionClass) {
		return FindingCandidate{}, errors.New("invalid validated finding candidate")
	}
	refs := uniqueRefs(evidenceRefs)
	if len(refs) == 0 {
		return FindingCandidate{}, errors.New("validated finding candidate requires evidence")
	}
	fingerprint := findingFingerprint(candidate)
	return FindingCandidate{FindingID: fingerprint, ProjectID: candidate.ProjectID, RunID: candidate.RunID, ValidationID: candidate.ValidationID, EndpointID: candidate.EndpointID, ParameterID: candidate.ParameterID, Class: candidate.InjectionClass, Title: "Validated injection behavior requires review", Description: "Bounded repeated validation observed a project-scoped structural response difference.", Confidence: result.Confidence, SeverityHint: severityHint(candidate.InjectionClass), EvidenceRefs: refs, Fingerprint: fingerprint, Status: FindingCandidateValidated}, nil
}

func findingFingerprint(candidate ValidationCandidate) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{candidate.ProjectID, candidate.EndpointID, candidate.ParameterID, string(candidate.InjectionClass), candidate.Fingerprint}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func severityHint(class injection.InjectionClass) string {
	switch class {
	case injection.ClassSQL, injection.ClassNoSQL, injection.ClassSSTI, injection.ClassCommand:
		return "medium"
	default:
		return "low"
	}
}

func uniqueRefs(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
