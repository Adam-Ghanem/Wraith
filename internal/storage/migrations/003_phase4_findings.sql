CREATE TABLE port_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain_or_ip TEXT NOT NULL,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL,
    service TEXT NOT NULL,
    banner TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('native', 'nmap')),
    discovered_at TEXT NOT NULL
);

CREATE INDEX port_findings_scan_target_port_idx ON port_findings(scan_id, subdomain_or_ip, port, protocol, source);

CREATE TABLE vuln_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_url TEXT NOT NULL,
    description TEXT NOT NULL,
    discovered_at TEXT NOT NULL
);

CREATE INDEX vuln_findings_scan_subdomain_template_idx ON vuln_findings(scan_id, subdomain, template_id, matched_url);
