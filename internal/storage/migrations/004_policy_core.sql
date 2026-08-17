CREATE TABLE project_scope_versions (
    version_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    authorization_owner_id TEXT NOT NULL,
    authorization_actions_json TEXT NOT NULL,
    authorization_expires_at TEXT,
    authorization_revoked_at TEXT,
    authorization_created_at TEXT NOT NULL
);

CREATE INDEX idx_project_scope_versions_project ON project_scope_versions(project_id, authorization_created_at DESC);

CREATE TABLE scope_rules (
    scope_version_id TEXT NOT NULL,
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    target_type TEXT NOT NULL CHECK (target_type IN ('domain', 'url', 'ipv4_cidr', 'ipv6_cidr')),
    value TEXT NOT NULL,
    ports_json TEXT NOT NULL,
    protocols_json TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope_version_id, id),
    FOREIGN KEY (scope_version_id) REFERENCES project_scope_versions(version_id) ON DELETE RESTRICT
);

CREATE INDEX idx_scope_rules_project ON scope_rules(project_id, scope_version_id);

CREATE TABLE active_project_scopes (
    project_id TEXT PRIMARY KEY,
    scope_version_id TEXT NOT NULL UNIQUE,
    activated_at TEXT NOT NULL,
    FOREIGN KEY (scope_version_id) REFERENCES project_scope_versions(version_id) ON DELETE RESTRICT
);
