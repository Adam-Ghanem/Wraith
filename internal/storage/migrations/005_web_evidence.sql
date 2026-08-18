CREATE TABLE web_assets (
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('url', 'javascript')),
    identity TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, identity)
);

CREATE INDEX idx_web_assets_project_url ON web_assets(project_id, canonical_url);

CREATE TABLE web_endpoints (
    project_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, identity)
);

CREATE INDEX idx_web_endpoints_project_url ON web_endpoints(project_id, url, method);

CREATE TABLE endpoint_parameters (
    project_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    endpoint_identity TEXT NOT NULL,
    location TEXT NOT NULL CHECK (location IN ('query', 'path', 'header', 'body', 'json')),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, identity),
    FOREIGN KEY (project_id, endpoint_identity) REFERENCES web_endpoints(project_id, identity) ON DELETE RESTRICT
);

CREATE INDEX idx_endpoint_parameters_project_endpoint ON endpoint_parameters(project_id, endpoint_identity);

CREATE TABLE evidence_observations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('http', 'technology', 'javascript', 'api_endpoint')),
    subject_identity TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1))
);

CREATE INDEX idx_evidence_observations_project_subject_time ON evidence_observations(project_id, subject_identity, observed_at, id);
