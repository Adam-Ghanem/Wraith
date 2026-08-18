CREATE TABLE IF NOT EXISTS intelligence_graph_nodes (
    project_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, node_id)
);
CREATE TABLE IF NOT EXISTS intelligence_graph_edges (
    project_id TEXT NOT NULL,
    from_node_id TEXT NOT NULL,
    edge_kind TEXT NOT NULL,
    to_node_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, from_node_id, edge_kind, to_node_id),
    FOREIGN KEY (project_id, from_node_id) REFERENCES intelligence_graph_nodes(project_id, node_id),
    FOREIGN KEY (project_id, to_node_id) REFERENCES intelligence_graph_nodes(project_id, node_id)
);
CREATE TABLE IF NOT EXISTS intelligence_correlations (
    project_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    subject_identity TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    confidence_score INTEGER NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, correlation_id)
);
CREATE INDEX IF NOT EXISTS idx_intelligence_correlations_project_subject ON intelligence_correlations(project_id, subject_identity, rule_id);
