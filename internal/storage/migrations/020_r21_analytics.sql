CREATE TABLE IF NOT EXISTS analytics_snapshots (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    window_from TEXT NOT NULL,
    window_to TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    source_fingerprints_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_analytics_snapshots_project_generated
    ON analytics_snapshots(project_id, generated_at, snapshot_fingerprint);
