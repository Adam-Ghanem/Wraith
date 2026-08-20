CREATE TABLE IF NOT EXISTS decision_snapshots (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    decision_version TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    source_fingerprints_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_decision_snapshots_project_generated ON decision_snapshots(project_id, generated_at, snapshot_fingerprint);

CREATE TABLE IF NOT EXISTS decision_candidates (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    priority TEXT NOT NULL,
    state TEXT NOT NULL,
    action TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint, candidate_fingerprint),
    FOREIGN KEY (project_id, snapshot_fingerprint) REFERENCES decision_snapshots(project_id, snapshot_fingerprint)
);
CREATE TABLE IF NOT EXISTS decision_factors (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    position INTEGER NOT NULL,
    factor_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint, candidate_fingerprint, position),
    FOREIGN KEY (project_id, snapshot_fingerprint, candidate_fingerprint) REFERENCES decision_candidates(project_id, snapshot_fingerprint, candidate_fingerprint)
);
CREATE TABLE IF NOT EXISTS decision_recommendations (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    recommendation_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint, candidate_fingerprint),
    FOREIGN KEY (project_id, snapshot_fingerprint, candidate_fingerprint) REFERENCES decision_candidates(project_id, snapshot_fingerprint, candidate_fingerprint)
);
CREATE TABLE IF NOT EXISTS decision_constraints (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    position INTEGER NOT NULL,
    constraint_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint, candidate_fingerprint, position),
    FOREIGN KEY (project_id, snapshot_fingerprint, candidate_fingerprint) REFERENCES decision_candidates(project_id, snapshot_fingerprint, candidate_fingerprint)
);
CREATE TABLE IF NOT EXISTS decision_lineage (
    project_id TEXT NOT NULL,
    snapshot_fingerprint TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    lineage_json TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_fingerprint, candidate_fingerprint),
    FOREIGN KEY (project_id, snapshot_fingerprint, candidate_fingerprint) REFERENCES decision_candidates(project_id, snapshot_fingerprint, candidate_fingerprint)
);
