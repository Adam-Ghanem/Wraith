CREATE TABLE IF NOT EXISTS authorization_audit_events (
    project_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    scope_reference TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, authorization_id, sequence),
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS authorization_audit_events_project_authorization_idx
    ON authorization_audit_events(project_id, authorization_id, sequence);
