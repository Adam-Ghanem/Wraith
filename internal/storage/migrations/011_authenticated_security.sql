CREATE TABLE IF NOT EXISTS identities (
    project_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('active', 'stopped', 'disabled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, identity_id),
    UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS sessions_metadata (
    project_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    PRIMARY KEY (project_id, session_id),
    FOREIGN KEY (project_id, identity_id) REFERENCES identities(project_id, identity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS authentication_targets (
    project_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, target_id)
);

CREATE TABLE IF NOT EXISTS authentication_runs (
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('bruteforce', 'spray', 'credential_list', 'enumeration', 'rate_limit')),
    status TEXT NOT NULL CHECK (status IN ('planned', 'completed', 'stopped', 'cancelled')),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 64),
    rate INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 20),
    concurrency INTEGER NOT NULL CHECK (concurrency BETWEEN 1 AND 2),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (project_id, run_id),
    FOREIGN KEY (project_id, target_id) REFERENCES authentication_targets(project_id, target_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS authentication_observations (
    project_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('success', 'failure', 'unknown', 'rate_limited', 'locked', 'mfa', 'captcha', 'server_error')),
    status_code INTEGER NOT NULL,
    body_fingerprint TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (project_id, observation_id),
    FOREIGN KEY (project_id, run_id) REFERENCES authentication_runs(project_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, identity_id) REFERENCES identities(project_id, identity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS lockout_observations (
    project_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('rate_limited', 'locked', 'mfa', 'captcha')),
    observed_at TEXT NOT NULL,
    PRIMARY KEY (project_id, observation_id),
    FOREIGN KEY (project_id, run_id) REFERENCES authentication_runs(project_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, identity_id) REFERENCES identities(project_id, identity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS identity_observations (
    project_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    endpoint_identity TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    body_fingerprint TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (project_id, observation_id),
    FOREIGN KEY (project_id, identity_id) REFERENCES identities(project_id, identity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS authorization_matrix (
    project_id TEXT NOT NULL,
    endpoint_identity TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    body_fingerprint TEXT NOT NULL,
    content_type TEXT NOT NULL,
    response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
    observed_at TEXT NOT NULL,
    PRIMARY KEY (project_id, endpoint_identity, identity_id),
    FOREIGN KEY (project_id, identity_id) REFERENCES identities(project_id, identity_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_authentication_observations_project_run ON authentication_observations(project_id, run_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_observations_project_identity ON identity_observations(project_id, identity_id, observed_at);
