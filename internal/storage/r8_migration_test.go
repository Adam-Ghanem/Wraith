package storage

import (
	"context"
	"testing"
)

func TestR8MigrationPreservesR75ContentObservations(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version >= 9;
DROP INDEX idx_evidence_observations_project_subject_time;
ALTER TABLE evidence_observations RENAME TO evidence_observations_r9;
CREATE TABLE evidence_observations (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('http','technology','javascript','api_endpoint','client_side','fuzz','content_discovery')), subject_identity TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL, payload_json TEXT NOT NULL, redacted INTEGER NOT NULL CHECK (redacted IN (0,1)));
INSERT INTO evidence_observations SELECT * FROM evidence_observations_r9;
DROP TABLE evidence_observations_r9;
CREATE INDEX idx_evidence_observations_project_subject_time ON evidence_observations(project_id, subject_identity, observed_at, id);
INSERT INTO evidence_observations VALUES ('r75-record','project-a','content_discovery','GET https://example.test/','content-discovery.r75.result','2026-08-18T00:00:00Z','{}',1);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	obs, err := db.ListObservations(ctx, "project-a", "GET https://example.test/")
	if err != nil || len(obs) != 1 || obs[0].Kind != "content_discovery" {
		t.Fatalf("obs=%#v err=%v", obs, err)
	}
}
