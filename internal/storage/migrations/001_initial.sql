CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    open_ports JSON NOT NULL DEFAULT '[]',
    os_guess TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(scan_id, ip)
);

CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    server_header TEXT NOT NULL DEFAULT '',
    tech_guess TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(scan_id, subdomain)
);

CREATE INDEX scans_target_completed_idx ON scans(target, completed_at DESC);
CREATE INDEX devices_scan_idx ON devices(scan_id);
CREATE INDEX subdomains_scan_idx ON subdomains(scan_id);
