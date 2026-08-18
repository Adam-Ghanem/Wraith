// R7 persistence stores only redacted structural observations through the R2 repository.
package fuzzing

import (
	"context"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func PersistAnalysis(ctx context.Context, repository evidence.Repository, projectID string, endpoint evidence.Endpoint, mutation Mutation, analysis ResponseAnalysis, observedAt time.Time) error {
	if repository == nil {
		return ErrInvalidExecution
	}
	record, err := evidence.NewFuzzObservation(projectID, endpoint, evidence.FuzzObservationInput{Source: "fuzz.response", ObservedAt: observedAt, MutationID: mutation.ID, MutationCategory: mutation.Category, SafetyClass: string(mutation.SafetyClass), StatusCode: analysis.StatusCode, ContentType: analysis.ContentType, ContentLength: analysis.ContentLength, DurationMS: analysis.DurationMS, Fingerprint: analysis.Fingerprint, StatusChanged: analysis.Baseline.StatusChanged, ContentTypeEqual: analysis.Baseline.ContentTypeEqual, LengthDelta: analysis.Baseline.LengthDelta, ReflectionLocation: analysis.Reflection.Location, ErrorClasses: append([]string(nil), analysis.ErrorClasses...), RedirectCount: analysis.RedirectCount})
	if err != nil {
		return err
	}
	return repository.AppendObservation(ctx, record.Record())
}
