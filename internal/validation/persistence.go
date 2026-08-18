package validation

import (
	"context"
	"errors"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"sort"
	"time"
)

func PersistResults(ctx context.Context, repo evidence.Repository, projectID string, endpoint evidence.Endpoint, results []Result, observedAt time.Time) error {
	if repo == nil || projectID == "" || endpoint.ProjectID != projectID || observedAt.IsZero() {
		return errors.New("invalid validation persistence")
	}
	ordered := append([]Result(nil), results...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ReproducibilityKey < ordered[j].ReproducibilityKey })
	for _, r := range ordered {
		if r.ReproducibilityKey == "" {
			return errors.New("invalid validation result")
		}
		o, err := evidence.NewValidationObservation(projectID, endpoint, evidence.ValidationObservationInput{Source: "validation.r8." + r.ValidatorID, ValidatorID: r.ValidatorID, RuleID: r.RuleID, Lifecycle: string(r.Lifecycle), ReproducibilityKey: r.ReproducibilityKey, ObservedAt: observedAt})
		if err != nil {
			return err
		}
		if err := repo.AppendObservation(ctx, o.Record()); err != nil {
			return err
		}
	}
	return nil
}
