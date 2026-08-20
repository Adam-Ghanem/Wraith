CREATE TABLE IF NOT EXISTS authorization_records (
    authorization_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope_reference TEXT NOT NULL,
    authorization_type TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    status TEXT NOT NULL,
    evidence_reference TEXT NOT NULL,
    created_by TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authorization_records_project_issued ON authorization_records(project_id, issued_at DESC, authorization_id);
