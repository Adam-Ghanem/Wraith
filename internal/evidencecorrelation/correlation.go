package evidencecorrelation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

type VerificationState string

const (
	Unsupported        VerificationState = "unsupported"
	PartiallySupported VerificationState = "partially_supported"
	Supported          VerificationState = "supported"
	StronglySupported  VerificationState = "strongly_supported"
	Stale              VerificationState = "stale"
	Contradictory      VerificationState = "contradictory"
	Invalid            VerificationState = "invalid"
)

type FreshnessState string

const (
	FreshnessCurrent FreshnessState = "current"
	FreshnessAging   FreshnessState = "aging"
	FreshnessStale   FreshnessState = "stale"
	FreshnessUnknown FreshnessState = "unknown"
)

type ReproducibilityState string

const (
	NotTested            ReproducibilityState = "not_tested"
	SingleObservation    ReproducibilityState = "single_observation"
	RepeatedConsistent   ReproducibilityState = "repeated_consistent"
	RepeatedInconsistent ReproducibilityState = "repeated_inconsistent"
	CannotReproduce      ReproducibilityState = "cannot_reproduce"
	InsufficientEvidence ReproducibilityState = "insufficient_evidence"
)

type ReferenceType string

const (
	ReferenceFinding     ReferenceType = "finding"
	ReferenceAsset       ReferenceType = "asset"
	ReferenceEndpoint    ReferenceType = "endpoint"
	ReferenceParameter   ReferenceType = "parameter"
	ReferenceObservation ReferenceType = "observation"
	ReferenceValidation  ReferenceType = "validation"
	ReferenceTask        ReferenceType = "campaign_task"
)

type EvidenceLink struct {
	ProjectID   string        `json:"project_id"`
	SourceID    string        `json:"source_id"`
	Relation    string        `json:"relation_type"`
	TargetID    string        `json:"target_id"`
	SourceType  ReferenceType `json:"source_type"`
	TargetType  ReferenceType `json:"target_type"`
	Fingerprint string        `json:"fingerprint"`
}

type EvidenceChain struct {
	ProjectID string         `json:"project_id"`
	FindingID string         `json:"finding_id"`
	Links     []EvidenceLink `json:"links"`
}

type Finding struct {
	ID, ProjectID, AssetID, EndpointID, ParameterID, ValidationID string
	EvidenceReferences                                            []string
	ValidatedAt                                                   time.Time
}

type Validation struct {
	ID, ProjectID, Status, Repeatability string
	At                                   time.Time
}

type Observation struct {
	ID, ProjectID, SubjectID string
	ObservedAt               time.Time
}

type CampaignTask struct {
	ID, ProjectID, CampaignID, Status, ResultReference string
	FinishedAt                                         time.Time
}

type FreshnessPolicy struct {
	AgingAfter, StaleAfter time.Duration
}

type Input struct {
	ProjectID     string
	Finding       Finding
	Validation    Validation
	Observations  []Observation
	CampaignTasks []CampaignTask
	Freshness     FreshnessPolicy
	Now           time.Time
}

type Result struct {
	ProjectID       string               `json:"project_id"`
	FindingID       string               `json:"finding_id"`
	Chain           EvidenceChain        `json:"evidence_chain"`
	Verification    VerificationState    `json:"verification"`
	Freshness       FreshnessState       `json:"freshness"`
	Reproducibility ReproducibilityState `json:"reproducibility"`
	Gaps            []string             `json:"gaps"`
	Contradictions  []string             `json:"contradictions"`
	Fingerprint     string               `json:"fingerprint"`
}

func Analyze(input Input) (Result, error) {
	if !validInput(input) {
		return Result{}, errors.New("invalid evidence correlation input")
	}
	result := Result{ProjectID: input.ProjectID, FindingID: input.Finding.ID, Chain: EvidenceChain{ProjectID: input.ProjectID, FindingID: input.Finding.ID, Links: []EvidenceLink{}}, Gaps: []string{}, Contradictions: []string{}}
	addFindingLink := func(relation string, targetType ReferenceType, targetID string) {
		if targetID == "" {
			return
		}
		result.Chain.Links = append(result.Chain.Links, newLink(input.ProjectID, ReferenceFinding, input.Finding.ID, relation, targetType, targetID))
	}
	if input.Finding.AssetID == "" {
		result.Gaps = append(result.Gaps, "ASSET_LINEAGE_MISSING")
	} else {
		addFindingLink("belongs_to", ReferenceAsset, input.Finding.AssetID)
	}
	if input.Finding.EndpointID == "" {
		result.Gaps = append(result.Gaps, "ENDPOINT_LINEAGE_MISSING")
	} else {
		addFindingLink("affects", ReferenceEndpoint, input.Finding.EndpointID)
	}
	if input.Finding.ParameterID == "" {
		result.Gaps = append(result.Gaps, "PARAMETER_LINEAGE_MISSING")
	} else {
		addFindingLink("affects", ReferenceParameter, input.Finding.ParameterID)
	}

	if input.Validation.ID == "" || input.Validation.ID != input.Finding.ValidationID || input.Validation.ProjectID != input.ProjectID {
		result.Gaps = append(result.Gaps, "VALIDATION_LINEAGE_MISSING")
	} else {
		addFindingLink("validated_by", ReferenceValidation, input.Validation.ID)
	}
	observationByID := make(map[string]Observation, len(input.Observations))
	foreignObservationIDs := make(map[string]bool, len(input.Observations))
	for _, observation := range input.Observations {
		if observation.ProjectID == input.ProjectID && validIdentifier(observation.ID) {
			observationByID[observation.ID] = observation
		} else if validIdentifier(observation.ID) {
			foreignObservationIDs[observation.ID] = true
		}
	}
	latestEvidence := time.Time{}
	for _, reference := range unique(input.Finding.EvidenceReferences) {
		observation, ok := observationByID[reference]
		if !ok {
			result.Gaps = append(result.Gaps, "OBSERVATION_MISSING")
			if foreignObservationIDs[reference] {
				result.Contradictions = append(result.Contradictions, "PROJECT_MISMATCH")
			}
			continue
		}
		addFindingLink("supported_by", ReferenceObservation, observation.ID)
		if observation.SubjectID != input.Finding.EndpointID {
			result.Contradictions = append(result.Contradictions, "OBSERVATION_SUBJECT_MISMATCH")
		} else {
			result.Chain.Links = append(result.Chain.Links, newLink(input.ProjectID, ReferenceObservation, observation.ID, "observes", ReferenceEndpoint, input.Finding.EndpointID))
		}
		if latestEvidence.IsZero() || observation.ObservedAt.After(latestEvidence) {
			latestEvidence = observation.ObservedAt
		}
	}
	if len(input.Finding.EvidenceReferences) == 0 {
		result.Gaps = append(result.Gaps, "OBSERVATION_MISSING")
	}

	var matchedTask *CampaignTask
	for i := range input.CampaignTasks {
		task := &input.CampaignTasks[i]
		if task.ProjectID == input.ProjectID && task.ResultReference == input.Validation.ID {
			if matchedTask == nil || task.FinishedAt.After(matchedTask.FinishedAt) || (task.FinishedAt.Equal(matchedTask.FinishedAt) && task.ID < matchedTask.ID) {
				matchedTask = task
			}
		}
	}
	if matchedTask == nil {
		result.Gaps = append(result.Gaps, "CAMPAIGN_LINEAGE_MISSING")
	} else {
		result.Chain.Links = append(result.Chain.Links, newLink(input.ProjectID, ReferenceValidation, input.Validation.ID, "produced_by", ReferenceTask, matchedTask.ID))
		if matchedTask.Status != "completed" {
			result.Gaps = append(result.Gaps, "TASK_OUTCOME_INCOMPLETE")
		}
		if !matchedTask.FinishedAt.IsZero() && !latestEvidence.IsZero() && matchedTask.FinishedAt.After(latestEvidence) {
			result.Contradictions = append(result.Contradictions, "CONTRADICTORY_TIMELINE")
		}
	}
	if !latestEvidence.IsZero() && !input.Validation.At.IsZero() && latestEvidence.After(input.Validation.At) {
		result.Contradictions = append(result.Contradictions, "CONTRADICTORY_TIMELINE")
	}
	if !input.Validation.At.IsZero() && !input.Finding.ValidatedAt.IsZero() && input.Validation.At.After(input.Finding.ValidatedAt) {
		result.Contradictions = append(result.Contradictions, "CONTRADICTORY_TIMELINE")
	}

	result.Freshness = classifyFreshness(latestEvidence, input.Now, input.Freshness)
	result.Reproducibility = classifyReproducibility(input.Validation, len(input.Finding.EvidenceReferences))
	sort.Strings(result.Gaps)
	result.Gaps = unique(result.Gaps)
	sort.Strings(result.Contradictions)
	result.Contradictions = unique(result.Contradictions)
	sort.Slice(result.Chain.Links, func(i, j int) bool { return linkKey(result.Chain.Links[i]) < linkKey(result.Chain.Links[j]) })
	if len(result.Contradictions) > 0 {
		result.Verification = Contradictory
	} else if result.Freshness == FreshnessStale {
		result.Verification = Stale
	} else if len(result.Gaps) > 0 {
		result.Verification = PartiallySupported
	} else if input.Validation.Status == "validated" && result.Reproducibility == RepeatedConsistent {
		result.Verification = StronglySupported
	} else if input.Validation.Status == "validated" {
		result.Verification = Supported
	} else {
		result.Verification = Unsupported
	}
	result.Fingerprint = fingerprint(result)
	return result, nil
}

func validInput(input Input) bool {
	return validIdentifier(input.ProjectID) && input.Finding.ProjectID == input.ProjectID && validIdentifier(input.Finding.ID) && validIdentifier(input.Finding.ValidationID) && !input.Now.IsZero() && input.Freshness.AgingAfter > 0 && input.Freshness.StaleAfter >= input.Freshness.AgingAfter
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 {
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

func newLink(projectID string, sourceType ReferenceType, sourceID, relation string, targetType ReferenceType, targetID string) EvidenceLink {
	link := EvidenceLink{ProjectID: projectID, SourceType: sourceType, SourceID: sourceID, Relation: relation, TargetType: targetType, TargetID: targetID}
	sum := sha256.Sum256([]byte(linkKey(link)))
	link.Fingerprint = hex.EncodeToString(sum[:])
	return link
}
func linkKey(link EvidenceLink) string {
	return strings.Join([]string{link.ProjectID, string(link.SourceType), link.SourceID, link.Relation, string(link.TargetType), link.TargetID}, "\x00")
}
func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
func classifyFreshness(observedAt, now time.Time, policy FreshnessPolicy) FreshnessState {
	if observedAt.IsZero() {
		return FreshnessUnknown
	}
	age := now.Sub(observedAt)
	if age < 0 {
		return FreshnessUnknown
	}
	if age >= policy.StaleAfter {
		return FreshnessStale
	}
	if age >= policy.AgingAfter {
		return FreshnessAging
	}
	return FreshnessCurrent
}
func classifyReproducibility(validation Validation, evidenceCount int) ReproducibilityState {
	if validation.ID == "" {
		return NotTested
	}
	if validation.Status != "validated" {
		return CannotReproduce
	}
	if validation.Repeatability == "repeatable" {
		return RepeatedConsistent
	}
	if validation.Repeatability == "partially_repeatable" || evidenceCount == 1 {
		return SingleObservation
	}
	return InsufficientEvidence
}
func fingerprint(result Result) string {
	payload := struct {
		ProjectID, FindingID string
		Chain                EvidenceChain
		Verification         VerificationState
		Freshness            FreshnessState
		Reproducibility      ReproducibilityState
		Gaps, Contradictions []string
	}{result.ProjectID, result.FindingID, result.Chain, result.Verification, result.Freshness, result.Reproducibility, result.Gaps, result.Contradictions}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
