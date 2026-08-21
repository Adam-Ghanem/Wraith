CREATE TABLE IF NOT EXISTS data_protection_snapshots (
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    descriptor_fingerprint TEXT NOT NULL,
    decision_fingerprint TEXT NOT NULL,
    profile TEXT NOT NULL,
    classification TEXT NOT NULL,
    version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_id),
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_data_protection_snapshots_project_created
    ON data_protection_snapshots(project_id, created_at, snapshot_id);
