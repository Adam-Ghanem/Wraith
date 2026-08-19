package storage

import (
	"context"
	"testing"
	"time"
)

func TestAttackSurfaceSnapshotStorageIsProjectScoped(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot := AttackSurfaceSnapshotRecord{SnapshotID: "snapshot-1", ProjectID: "alpha", GraphFingerprint: "graph-1", SourceVersion: "r11.6-v1", CreatedAt: time.Unix(1, 0), NodeCount: 2, EdgeCount: 1}
	nodes := []AttackSurfaceNodeRecord{{NodeID: "project:alpha", ProjectID: "alpha", NodeType: "project", Reference: "alpha"}, {NodeID: "asset:asset-1", ProjectID: "alpha", NodeType: "asset", Reference: "asset-1"}}
	edges := []AttackSurfaceEdgeRecord{{EdgeID: "edge-1", ProjectID: "alpha", SourceNodeID: "project:alpha", Relationship: "owns", DestinationNodeID: "asset:asset-1"}}
	if err := database.SaveAttackSurfaceSnapshot(ctx, snapshot, nodes, edges); err != nil {
		t.Fatal(err)
	}
	loaded, loadedNodes, loadedEdges, err := database.LoadAttackSurfaceSnapshot(ctx, "alpha", "snapshot-1")
	if err != nil || loaded.SnapshotID != "snapshot-1" || len(loadedNodes) != 2 || len(loadedEdges) != 1 {
		t.Fatalf("snapshot=%#v nodes=%#v edges=%#v err=%v", loaded, loadedNodes, loadedEdges, err)
	}
	if _, _, _, err := database.LoadAttackSurfaceSnapshot(ctx, "beta", "snapshot-1"); err == nil {
		t.Fatal("expected cross-project snapshot lookup rejection")
	}
}
