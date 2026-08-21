package storage

import (
	"context"
	"testing"
)

func TestR75MigrationPreservesR7FuzzObservations(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.sql.ExecContext(ctx, `
DELETE FROM schema_migrations WHERE version >= 8;
DROP INDEX idx_evidence_observations_project_subject_time;
ALTER TABLE evidence_observations RENAME TO evidence_observations_r8;
CREATE TABLE evidence_observations (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('http', 'technology', 'javascript', 'api_endpoint', 'client_side', 'fuzz')),
    subject_identity TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL, redacted INTEGER NOT NULL CHECK (redacted IN (0, 1))
);
INSERT INTO evidence_observations(id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted)
SELECT id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted FROM evidence_observations_r8;
DROP TABLE evidence_observations_r8;
CREATE INDEX idx_evidence_observations_project_subject_time ON evidence_observations(project_id, subject_identity, observed_at, id);
INSERT INTO evidence_observations(id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted)
VALUES ('r7-record', 'project-a', 'fuzz', 'GET https://example.test/api', 'fuzz.response', '2026-08-18T00:00:00Z', '{}', 1);`); err != nil {
		t.Fatalf("simulate R7 observation table: %v", err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate R7 observations to R7.5: %v", err)
	}
	observations, err := database.ListObservations(ctx, "project-a", "GET https://example.test/api")
	if err != nil || len(observations) != 1 || observations[0].ID != "r7-record" || observations[0].Kind != "fuzz" {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	if version := database.CurrentSchemaVersion(ctx); version != CurrentSchemaVersion {
		t.Fatalf("schema version=%d want=%d", version, CurrentSchemaVersion)
	}
}
