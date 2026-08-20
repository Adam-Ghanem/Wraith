CREATE TABLE IF NOT EXISTS evidence_correlation_snapshots (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    verification_state TEXT NOT NULL,
    freshness_state TEXT NOT NULL,
    reproducibility_state TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, campaign_id, finding_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_evidence_correlation_project_campaign_created ON evidence_correlation_snapshots(project_id, campaign_id, created_at, finding_id);
