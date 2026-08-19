package findingvalidation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/intelligence"
	"github.com/Adam-Ghanem/Wraith/internal/validation"
)

type ValidationEvidenceSink interface {
	UpsertEndpoint(context.Context, evidence.Endpoint) (evidence.Endpoint, error)
	AppendObservation(context.Context, evidence.Observation) error
}

// R8Adapter delegates response evaluation and observation lifecycle keys to R8
// and records only redacted R2 validation observations.
type R8Adapter struct{ Evidence ValidationEvidenceSink }

func (adapter R8Adapter) Submit(ctx context.Context, candidate ValidationCandidate, result ValidationResult, endpoint evidence.Endpoint, response httpengine.Response) ([]string, error) {
	if adapter.Evidence == nil || candidate.ProjectID == "" || candidate.ProjectID != endpoint.ProjectID || candidate.ValidationID != result.ValidationID || result.Status != StatusValidated {
		return nil, errors.New("invalid R8 validation handoff")
	}
	endpoint, err := adapter.Evidence.UpsertEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	validators := append(validation.DefaultValidators(), injectionValidator{candidate: candidate, result: result})
	results, err := validation.Run(validation.Input{ProjectID: candidate.ProjectID, Endpoint: endpoint, ObservedAt: time.Now().UTC(), StatusCode: response.StatusCode, Headers: response.Headers, Body: response.Body}, validators)
	if err != nil {
		return nil, err
	}
	references := make([]string, 0, len(results))
	for _, validationResult := range results {
		observation, err := evidence.NewValidationObservation(candidate.ProjectID, endpoint, evidence.ValidationObservationInput{Source: "validation.r8.r11.4", ValidatorID: validationResult.ValidatorID, RuleID: validationResult.RuleID, Lifecycle: string(validationResult.Lifecycle), ReproducibilityKey: validationResult.ReproducibilityKey, ObservedAt: time.Now().UTC()})
		if err != nil {
			return nil, err
		}
		if err := adapter.Evidence.AppendObservation(ctx, observation.Record()); err != nil {
			return nil, err
		}
		references = append(references, observation.ID)
	}
	return uniqueRefs(references), nil
}

type injectionValidator struct {
	candidate ValidationCandidate
	result    ValidationResult
}

func (validator injectionValidator) ID() string { return "injection-r11.4" }

func (validator injectionValidator) Validate(_ validation.Input) []validation.Result {
	if validator.result.Status != StatusValidated {
		return nil
	}
	return []validation.Result{{ValidatorID: validator.ID(), RuleID: "repeatable-" + string(validator.candidate.InjectionClass), Title: "Repeatable injection response behavior", Evidence: "bounded repeated structural differential"}}
}

// R9Adapter translates only validated, evidence-backed R11.4 candidates into
// existing R9 candidates. R9 remains responsible for all correlation results.
type R9Adapter struct{}

func (R9Adapter) Submit(_ context.Context, candidate FindingCandidate) (string, error) {
	if candidate.ProjectID == "" || candidate.Status != FindingCandidateValidated || candidate.EndpointID == "" || candidate.ParameterID == "" || len(candidate.EvidenceRefs) == 0 {
		return "", errors.New("invalid R9 correlation handoff")
	}
	correlations, err := intelligence.Correlate(candidate.ProjectID, []intelligence.Candidate{{ProjectID: candidate.ProjectID, RuleID: "injection." + string(candidate.Class), SubjectIdentity: strings.Join([]string{candidate.EndpointID, candidate.ParameterID}, "|"), EvidenceIDs: candidate.EvidenceRefs, ObservedAt: time.Now().UTC()}})
	if err != nil || len(correlations) != 1 {
		if err == nil {
			err = errors.New("missing R9 correlation")
		}
		return "", err
	}
	return correlations[0].ID, nil
}
