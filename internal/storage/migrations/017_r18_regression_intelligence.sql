CREATE TABLE IF NOT EXISTS regression_snapshots (
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    scope_version TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    surface_snapshot_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_id)
);

CREATE INDEX IF NOT EXISTS idx_regression_snapshots_project_created ON regression_snapshots(project_id, created_at, snapshot_id);

CREATE TABLE IF NOT EXISTS regression_comparisons (
    project_id TEXT NOT NULL,
    baseline_snapshot_id TEXT NOT NULL,
    current_snapshot_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    comparison_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, baseline_snapshot_id, current_snapshot_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_regression_comparisons_project_created ON regression_comparisons(project_id, created_at, fingerprint);
