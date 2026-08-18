package validation

import (
	"context"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistResultsStoresProjectScopedRedactedEvidence(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "r8.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ep, _ := evidence.NewEndpoint("project-a", "GET", "https://example.test/", time.Unix(0, 0).UTC())
	if _, err := db.UpsertEndpoint(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	results, err := Run(Input{ProjectID: "project-a", Endpoint: ep, ObservedAt: time.Unix(0, 0).UTC(), Headers: map[string][]string{"Server": {"nginx/1.2"}}}, DefaultValidators())
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistResults(context.Background(), db, "project-a", ep, results, time.Unix(0, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	obs, err := db.ListObservations(context.Background(), "project-a", ep.Identity)
	if err != nil || len(obs) != 3 || !obs[0].Redacted || !obs[1].Redacted || !obs[2].Redacted {
		t.Fatalf("obs=%#v err=%v", obs, err)
	}
}
