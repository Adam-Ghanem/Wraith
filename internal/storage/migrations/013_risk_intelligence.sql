CREATE TABLE IF NOT EXISTS security_findings (
    project_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    validation_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    parameter_id TEXT NOT NULL,
    asset_id TEXT NOT NULL DEFAULT '',
    class TEXT NOT NULL,
    subtype TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation_hint TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    severity TEXT NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_band TEXT NOT NULL CHECK (risk_band IN ('informational', 'low', 'medium', 'high', 'critical')),
    risk_model_version TEXT NOT NULL,
    risk_factors_json TEXT NOT NULL,
    risk_reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'accepted', 'false_positive', 'resolved', 'reopened', 'suppressed')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    PRIMARY KEY (project_id, finding_id),
    UNIQUE (project_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS finding_history (
    project_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    event TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (project_id, event_id),
    FOREIGN KEY (project_id, finding_id) REFERENCES security_findings(project_id, finding_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    project_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    band TEXT NOT NULL CHECK (band IN ('informational', 'low', 'medium', 'high', 'critical')),
    factors_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    calculated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, finding_id, model_version),
    FOREIGN KEY (project_id, finding_id) REFERENCES security_findings(project_id, finding_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS finding_suppressions (
    project_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_security_findings_project_status ON security_findings(project_id, status, risk_score DESC, finding_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_project_severity ON security_findings(project_id, severity, risk_score DESC, finding_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_project_asset ON security_findings(project_id, asset_id, risk_score DESC, finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_history_project_finding_time ON finding_history(project_id, finding_id, occurred_at, event_id);
