CREATE TABLE IF NOT EXISTS data_governance_policies (
    project_id TEXT NOT NULL,
    version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    canonical_rules TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, version),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_data_governance_policies_project_created ON data_governance_policies(project_id, created_at);

CREATE TABLE IF NOT EXISTS data_classification_records (
    project_id TEXT NOT NULL,
    subject_reference TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    provenance_reference TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, subject_reference, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_data_classification_records_project_subject ON data_classification_records(project_id, subject_reference);

CREATE TABLE IF NOT EXISTS data_governance_decisions (
    project_id TEXT NOT NULL,
    subject_reference TEXT NOT NULL,
    action TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    classification TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    consumer TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_data_governance_decisions_project_subject ON data_governance_decisions(project_id, subject_reference, occurred_at);

CREATE TABLE IF NOT EXISTS data_retention_records (
    project_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    subject_reference TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retain_until TEXT NOT NULL,
    hold INTEGER NOT NULL CHECK (hold IN (0, 1)),
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, fingerprint),
    UNIQUE (project_id, subject_reference, policy_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_data_retention_records_project_until ON data_retention_records(project_id, retain_until);

CREATE TABLE IF NOT EXISTS data_governance_events (
    project_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    subject_reference TEXT NOT NULL,
    classification TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_data_governance_events_project_occurred ON data_governance_events(project_id, occurred_at);
