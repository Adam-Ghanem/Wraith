ALTER TABLE evidence_observations RENAME TO evidence_observations_r6;

CREATE TABLE evidence_observations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('http', 'technology', 'javascript', 'api_endpoint', 'client_side', 'fuzz')),
    subject_identity TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1))
);

INSERT INTO evidence_observations(id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted)
SELECT id, project_id, kind, subject_identity, source, observed_at, payload_json, redacted
FROM evidence_observations_r6;

DROP TABLE evidence_observations_r6;

CREATE INDEX idx_evidence_observations_project_subject_time ON evidence_observations(project_id, subject_identity, observed_at, id);
