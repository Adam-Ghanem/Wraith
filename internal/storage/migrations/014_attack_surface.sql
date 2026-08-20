CREATE TABLE IF NOT EXISTS attack_surface_nodes (
    project_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    PRIMARY KEY (project_id, node_id)
);
CREATE TABLE IF NOT EXISTS attack_surface_edges (
    project_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    destination_node_id TEXT NOT NULL,
    PRIMARY KEY (project_id, edge_id),
    UNIQUE (project_id, source_node_id, relationship, destination_node_id),
    FOREIGN KEY (project_id, source_node_id) REFERENCES attack_surface_nodes(project_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, destination_node_id) REFERENCES attack_surface_nodes(project_id, node_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS attack_surface_snapshots (
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    graph_fingerprint TEXT NOT NULL,
    source_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    node_count INTEGER NOT NULL CHECK (node_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    PRIMARY KEY (project_id, snapshot_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_nodes_project_type ON attack_surface_nodes(project_id, node_type, node_id);
CREATE INDEX IF NOT EXISTS idx_attack_surface_edges_project_source ON attack_surface_edges(project_id, source_node_id, relationship, destination_node_id);
CREATE INDEX IF NOT EXISTS idx_attack_surface_snapshots_project_created ON attack_surface_snapshots(project_id, created_at, snapshot_id);
