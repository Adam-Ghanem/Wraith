CREATE TABLE content_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_length INTEGER NOT NULL,
    discovered_at TEXT NOT NULL
);

CREATE INDEX content_findings_scan_subdomain_path_idx ON content_findings(scan_id, subdomain, path);

CREATE TABLE js_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    source_file TEXT NOT NULL,
    finding_type TEXT NOT NULL CHECK(finding_type IN ('endpoint', 'secret')),
    value TEXT NOT NULL,
    confidence TEXT NOT NULL,
    discovered_at TEXT NOT NULL
);

CREATE INDEX js_findings_scan_subdomain_idx ON js_findings(scan_id, subdomain);
