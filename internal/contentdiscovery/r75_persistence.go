// R7.5 persistence stores redacted R2 evidence only; it never stores response bodies.
package contentdiscovery

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

// PersistR75Results creates project-local URL assets, GET endpoints, and bounded HTTP observations.
func PersistR75Results(ctx context.Context, repository evidence.Repository, projectID string, results []R75Result, observedAt time.Time) error {
	if repository == nil || strings.TrimSpace(projectID) == "" || observedAt.IsZero() {
		return ErrInvalidR75Execution
	}
	ordered := append([]R75Result(nil), results...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].URL < ordered[j].URL })
	for _, result := range ordered {
		if strings.TrimSpace(result.URL) == "" || !r75PersistableStatus(result.StatusCode) || result.ContentLength < 0 || result.ContentLength > 4<<20 || len(result.ContentType) > 1024 || len(result.Fingerprint) > 128 {
			return ErrInvalidR75Execution
		}
		asset, err := evidence.NewWebAsset(projectID, evidence.AssetKindURL, result.URL, observedAt)
		if err != nil {
			return err
		}
		if _, err := repository.UpsertWebAsset(ctx, asset); err != nil {
			return err
		}
		endpoint, err := evidence.NewEndpoint(projectID, http.MethodGet, result.URL, observedAt)
		if err != nil {
			return err
		}
		if _, err := repository.UpsertEndpoint(ctx, endpoint); err != nil {
			return err
		}
		observation, err := evidence.NewContentDiscoveryObservation(projectID, endpoint, evidence.ContentDiscoveryObservationInput{Source: "content-discovery.r75.result", ObservedAt: observedAt, StatusCode: result.StatusCode, ContentType: result.ContentType, ContentClass: result.ContentClass, ContentLength: result.ContentLength, Fingerprint: result.Fingerprint, BaselineSimilarity: result.Similarity, RedirectCount: result.RedirectCount, DurationMS: result.DurationMS})
		if err != nil {
			return err
		}
		if err := repository.AppendObservation(ctx, observation.Record()); err != nil {
			return err
		}
	}
	return nil
}

func r75PersistableStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode <= 399 || statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}
