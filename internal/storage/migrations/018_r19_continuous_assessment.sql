CREATE TABLE IF NOT EXISTS assessment_policies (
    project_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    name TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, policy_id),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_assessment_policies_project_created ON assessment_policies(project_id, created_at, policy_id);

CREATE TABLE IF NOT EXISTS assessment_baselines (
    project_id TEXT NOT NULL,
    baseline_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    campaign_id TEXT,
    fingerprint TEXT NOT NULL,
    baseline_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, baseline_id),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_assessment_baselines_project_policy_snapshot ON assessment_baselines(project_id, policy_id, snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_assessment_baselines_project_campaign ON assessment_baselines(project_id, campaign_id, created_at);

CREATE TABLE IF NOT EXISTS assessment_evaluations (
    project_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    baseline_id TEXT NOT NULL,
    baseline_snapshot_id TEXT NOT NULL,
    current_snapshot_id TEXT NOT NULL,
    comparison_id TEXT NOT NULL,
    status TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    evaluation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, evaluation_id),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_assessment_evaluations_project_policy_baseline ON assessment_evaluations(project_id, policy_id, baseline_id, created_at);
CREATE INDEX IF NOT EXISTS idx_assessment_evaluations_project_current_snapshot ON assessment_evaluations(project_id, current_snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_assessment_evaluations_project_status ON assessment_evaluations(project_id, status, created_at);

CREATE TABLE IF NOT EXISTS assessment_actions (
    project_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    campaign_id TEXT,
    fingerprint TEXT NOT NULL,
    action_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, action_id),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_assessment_actions_project_evaluation ON assessment_actions(project_id, evaluation_id, created_at, action_id);
CREATE INDEX IF NOT EXISTS idx_assessment_actions_project_status ON assessment_actions(project_id, status, created_at);
