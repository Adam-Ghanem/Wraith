package fuzzing

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPersistAnalysisAppendsOnlyRedactedProjectScopedFuzzEvidence(t *testing.T) {
	ctx := context.Background()
	database, err := storage.Open(filepath.Join(t.TempDir(), "wraith.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	endpoint, err := evidence.NewEndpoint("project-a", "GET", "https://example.test/api/users", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	analysis := AnalyzeResponse(nil, Mutation{ID: "minimal/one-char", Category: "boundary", Value: "sensitive-value", SafetyClass: SafetyGeneric}, httpengine.Response{StatusCode: 500, ContentType: "application/json", Body: []byte(`{"error":"type error"}`), Duration: time.Millisecond})
	if err := PersistAnalysis(ctx, database, "project-a", endpoint, Mutation{ID: "minimal/one-char", Category: "boundary", Value: "sensitive-value", SafetyClass: SafetyGeneric}, analysis, now); err != nil {
		t.Fatal(err)
	}
	observations, err := database.ListObservations(ctx, "project-a", endpoint.Identity)
	if err != nil || len(observations) != 1 || observations[0].Kind != evidence.ObservationKindFuzz || !observations[0].Redacted || strings.Contains(string(observations[0].Payload), "sensitive-value") {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
}
