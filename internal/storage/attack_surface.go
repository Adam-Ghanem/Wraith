package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AttackSurfaceNodeRecord struct{ NodeID, ProjectID, NodeType, Reference string }
type AttackSurfaceEdgeRecord struct{ EdgeID, ProjectID, SourceNodeID, Relationship, DestinationNodeID string }
type AttackSurfaceSnapshotRecord struct {
	SnapshotID, ProjectID, GraphFingerprint, SourceVersion string
	CreatedAt                                              time.Time
	NodeCount, EdgeCount                                   int
}

func (db *DB) SaveAttackSurfaceSnapshot(ctx context.Context, snapshot AttackSurfaceSnapshotRecord, nodes []AttackSurfaceNodeRecord, edges []AttackSurfaceEdgeRecord) error {
	if db == nil || db.sql == nil || strings.TrimSpace(snapshot.ProjectID) == "" || strings.TrimSpace(snapshot.SnapshotID) == "" || strings.TrimSpace(snapshot.GraphFingerprint) == "" || strings.TrimSpace(snapshot.SourceVersion) == "" || snapshot.CreatedAt.IsZero() || snapshot.NodeCount != len(nodes) || snapshot.EdgeCount != len(edges) {
		return errors.New("invalid attack surface snapshot")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, node := range nodes {
		if node.ProjectID != snapshot.ProjectID || strings.TrimSpace(node.NodeID) == "" || strings.TrimSpace(node.NodeType) == "" || strings.TrimSpace(node.Reference) == "" {
			return errors.New("invalid attack surface node")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO attack_surface_nodes(project_id,node_id,node_type,reference_id) VALUES(?,?,?,?) ON CONFLICT(project_id,node_id) DO UPDATE SET node_type=excluded.node_type, reference_id=excluded.reference_id`, node.ProjectID, node.NodeID, node.NodeType, node.Reference); err != nil {
			return fmt.Errorf("save attack surface node: %w", err)
		}
	}
	for _, edge := range edges {
		if edge.ProjectID != snapshot.ProjectID || strings.TrimSpace(edge.EdgeID) == "" || strings.TrimSpace(edge.SourceNodeID) == "" || strings.TrimSpace(edge.Relationship) == "" || strings.TrimSpace(edge.DestinationNodeID) == "" {
			return errors.New("invalid attack surface edge")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO attack_surface_edges(project_id,edge_id,source_node_id,relationship,destination_node_id) VALUES(?,?,?,?,?) ON CONFLICT(project_id,edge_id) DO NOTHING`, edge.ProjectID, edge.EdgeID, edge.SourceNodeID, edge.Relationship, edge.DestinationNodeID); err != nil {
			return fmt.Errorf("save attack surface edge: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO attack_surface_snapshots(project_id,snapshot_id,graph_fingerprint,source_version,created_at,node_count,edge_count) VALUES(?,?,?,?,?,?,?) ON CONFLICT(project_id,snapshot_id) DO NOTHING`, snapshot.ProjectID, snapshot.SnapshotID, snapshot.GraphFingerprint, snapshot.SourceVersion, snapshot.CreatedAt.UTC().Format(time.RFC3339Nano), snapshot.NodeCount, snapshot.EdgeCount); err != nil {
		return fmt.Errorf("save attack surface snapshot: %w", err)
	}
	return tx.Commit()
}

func (db *DB) LoadAttackSurfaceSnapshot(ctx context.Context, projectID, snapshotID string) (AttackSurfaceSnapshotRecord, []AttackSurfaceNodeRecord, []AttackSurfaceEdgeRecord, error) {
	if db == nil || db.sql == nil || strings.TrimSpace(projectID) == "" || strings.TrimSpace(snapshotID) == "" {
		return AttackSurfaceSnapshotRecord{}, nil, nil, errors.New("invalid attack surface snapshot query")
	}
	var snapshot AttackSurfaceSnapshotRecord
	var created string
	if err := db.sql.QueryRowContext(ctx, `SELECT project_id,snapshot_id,graph_fingerprint,source_version,created_at,node_count,edge_count FROM attack_surface_snapshots WHERE project_id=? AND snapshot_id=?`, projectID, snapshotID).Scan(&snapshot.ProjectID, &snapshot.SnapshotID, &snapshot.GraphFingerprint, &snapshot.SourceVersion, &created, &snapshot.NodeCount, &snapshot.EdgeCount); err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	var err error
	if snapshot.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	nodeRows, err := db.sql.QueryContext(ctx, `SELECT project_id,node_id,node_type,reference_id FROM attack_surface_nodes WHERE project_id=? ORDER BY node_id`, projectID)
	if err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	defer nodeRows.Close()
	nodes := make([]AttackSurfaceNodeRecord, 0)
	for nodeRows.Next() {
		var node AttackSurfaceNodeRecord
		if err := nodeRows.Scan(&node.ProjectID, &node.NodeID, &node.NodeType, &node.Reference); err != nil {
			return AttackSurfaceSnapshotRecord{}, nil, nil, err
		}
		nodes = append(nodes, node)
	}
	if err := nodeRows.Err(); err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	edgeRows, err := db.sql.QueryContext(ctx, `SELECT project_id,edge_id,source_node_id,relationship,destination_node_id FROM attack_surface_edges WHERE project_id=? ORDER BY source_node_id,relationship,destination_node_id`, projectID)
	if err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	defer edgeRows.Close()
	edges := make([]AttackSurfaceEdgeRecord, 0)
	for edgeRows.Next() {
		var edge AttackSurfaceEdgeRecord
		if err := edgeRows.Scan(&edge.ProjectID, &edge.EdgeID, &edge.SourceNodeID, &edge.Relationship, &edge.DestinationNodeID); err != nil {
			return AttackSurfaceSnapshotRecord{}, nil, nil, err
		}
		edges = append(edges, edge)
	}
	if err := edgeRows.Err(); err != nil {
		return AttackSurfaceSnapshotRecord{}, nil, nil, err
	}
	return snapshot, nodes, edges, nil
}
