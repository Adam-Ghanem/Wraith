CREATE TABLE IF NOT EXISTS campaigns (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    scope_version TEXT NOT NULL,
    profile TEXT NOT NULL CHECK (profile IN ('safe', 'standard', 'deep')),
    assessment_id TEXT NOT NULL,
    target TEXT NOT NULL,
    assessment_plan_json TEXT NOT NULL,
    surface_snapshot_id TEXT NOT NULL,
    surface_fingerprint TEXT NOT NULL,
    surface_source_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'planned', 'ready', 'running', 'paused', 'completed', 'failed', 'cancelled', 'expired')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    fingerprint TEXT NOT NULL,
    last_checkpoint_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    cancelled_at TEXT,
    PRIMARY KEY (project_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS campaign_cycles (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    scope_version TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    surface_snapshot_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'planned', 'ready', 'running', 'paused', 'completed', 'failed', 'cancelled', 'expired')),
    execution_run_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY (project_id, campaign_id, cycle_id),
    FOREIGN KEY (project_id, campaign_id) REFERENCES campaigns(project_id, campaign_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS campaign_tasks (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    assessment_task_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'ready', 'running', 'completed', 'failed', 'blocked', 'skipped', 'cancelled', 'expired')),
    priority INTEGER NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 0),
    result_reference TEXT NOT NULL DEFAULT '',
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY (project_id, campaign_id, cycle_id, task_id),
    UNIQUE (project_id, campaign_id, cycle_id, assessment_task_id),
    FOREIGN KEY (project_id, campaign_id, cycle_id) REFERENCES campaign_cycles(project_id, campaign_id, cycle_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS campaign_checkpoints (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    scope_version TEXT NOT NULL,
    surface_snapshot_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    completed_task_ids_json TEXT NOT NULL,
    pending_task_ids_json TEXT NOT NULL,
    blocked_task_ids_json TEXT NOT NULL,
    failed_task_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, campaign_id, checkpoint_id),
    UNIQUE (project_id, campaign_id, cycle_id, sequence),
    FOREIGN KEY (project_id, campaign_id, cycle_id) REFERENCES campaign_cycles(project_id, campaign_id, cycle_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS campaign_events (
    project_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, campaign_id, event_id),
    FOREIGN KEY (project_id, campaign_id) REFERENCES campaigns(project_id, campaign_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_campaigns_project_created ON campaigns(project_id, created_at, campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_cycles_project_campaign_created ON campaign_cycles(project_id, campaign_id, created_at, cycle_id);
CREATE INDEX IF NOT EXISTS idx_campaign_tasks_project_cycle_status ON campaign_tasks(project_id, campaign_id, cycle_id, status, task_id);
CREATE INDEX IF NOT EXISTS idx_campaign_checkpoints_project_cycle_sequence ON campaign_checkpoints(project_id, campaign_id, cycle_id, sequence DESC);
CREATE INDEX IF NOT EXISTS idx_campaign_events_project_campaign_created ON campaign_events(project_id, campaign_id, created_at, event_id);
