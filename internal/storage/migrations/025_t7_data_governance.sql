ALTER TABLE evidence_observations ADD COLUMN classification TEXT NOT NULL DEFAULT 'internal';
ALTER TABLE evidence_observations ADD COLUMN policy_version TEXT NOT NULL DEFAULT 'legacy';

CREATE TABLE IF NOT EXISTS data_governance_audit_events (
    project_id TEXT NOT NULL,
    subject_reference TEXT NOT NULL,
    event_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS data_governance_audit_events_project_occurred_idx
    ON data_governance_audit_events(project_id, occurred_at, fingerprint);
