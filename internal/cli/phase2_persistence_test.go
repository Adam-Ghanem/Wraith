package cli

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/model"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPersistPhase1ResultWritesDiscoverScan(t *testing.T) {
	path := t.TempDir() + "/phase2.db"
	result := model.Result{
		Scope:   model.Scope{CIDR: "192.168.1.0/24"},
		Run:     model.Run{StartedAt: "2026-08-15T00:00:00Z", CompletedAt: "2026-08-15T00:01:00Z"},
		Targets: []model.Target{{IP: netip.MustParseAddr("192.168.1.10"), Ports: []model.PortResult{{Port: 80, Status: "open"}}}},
	}
	if err := persistPhase1Result(context.Background(), path, result); err != nil {
		t.Fatalf("persist Phase 1 result: %v", err)
	}
	database, err := storage.Open(path)
	if err != nil {
		t.Fatalf("open saved database: %v", err)
	}
	defer database.Close()
	latest, err := database.LatestScans(context.Background(), "192.168.1.0/24", 1)
	if err != nil || len(latest) != 1 || latest[0].ScanType != "discover" {
		t.Fatalf("expected saved discover scan, got %v %+v", err, latest)
	}
}
