CREATE TABLE IF NOT EXISTS governance_recommendation_states (
    project_id TEXT NOT NULL,
    recommendation_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    baseline_id TEXT NOT NULL,
    recommendation_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    state_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, recommendation_id, evaluation_id)
);

CREATE TABLE IF NOT EXISTS governance_decisions (
    project_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    recommendation_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    previous_state TEXT NOT NULL,
    next_state TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (project_id, decision_id)
);

CREATE TABLE IF NOT EXISTS governance_events (
    project_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    recommendation_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    event_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (project_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_governance_states_project_updated
    ON governance_recommendation_states(project_id, updated_at, recommendation_id);
CREATE INDEX IF NOT EXISTS idx_governance_events_project_recommendation
    ON governance_events(project_id, recommendation_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS idx_governance_decisions_project_recommendation
    ON governance_decisions(project_id, recommendation_id, occurred_at, decision_id);
