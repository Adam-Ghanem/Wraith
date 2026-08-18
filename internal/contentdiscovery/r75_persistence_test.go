package contentdiscovery

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPersistR75ResultsWritesOnlyProjectScopedR2Evidence(t *testing.T) {
	database, err := storage.Open(filepath.Join(t.TempDir(), "r75.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	results := []R75Result{{URL: "https://example.test/admin", Path: "/admin", StatusCode: 403, ContentType: "text/html", ContentClass: "html", ContentLength: 21, Fingerprint: "abc"}}
	if err := PersistR75Results(context.Background(), database, "project-a", results, time.Unix(0, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	endpoints, err := database.ListEndpoints(context.Background(), "project-a")
	if err != nil || len(endpoints) != 1 || endpoints[0].Identity != "GET https://example.test/admin" {
		t.Fatalf("endpoints=%#v err=%v", endpoints, err)
	}
	observations, err := database.ListObservations(context.Background(), "project-a", endpoints[0].Identity)
	if err != nil || len(observations) != 1 || observations[0].Source != "content-discovery.r75.result" || !observations[0].Redacted {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	if foreign, err := database.ListEndpoints(context.Background(), "project-b"); err != nil || len(foreign) != 0 {
		t.Fatalf("foreign=%#v err=%v", foreign, err)
	}
}
