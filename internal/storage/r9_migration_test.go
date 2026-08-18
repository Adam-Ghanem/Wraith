package storage

import (
	"context"
	"testing"
)

func TestR9MigrationCreatesProjectScopedIntelligenceTables(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('intelligence_graph_nodes','intelligence_graph_edges','intelligence_correlations')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("intelligence table count=%d", count)
	}
}
