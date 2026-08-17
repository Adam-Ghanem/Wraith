package storage

import (
	"context"
	"database/sql"
	"testing"
)

func TestDiffDevicesReportsNewRemovedAndChanged(t *testing.T) {
	previous := []DeviceSnapshot{
		{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:10", OpenPortsJSON: `[80]`},
		{IP: "192.168.1.11", MAC: "AA:AA:AA:AA:AA:11", OpenPortsJSON: `[22]`},
	}
	current := []DeviceSnapshot{
		{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:10", OpenPortsJSON: `[80,443]`},
		{IP: "192.168.1.12", MAC: "AA:AA:AA:AA:AA:12", OpenPortsJSON: `[53]`},
	}

	diff := DiffDevices(previous, current)
	if !hasDeviceChange(diff, ChangeChanged, "192.168.1.10") {
		t.Fatalf("expected changed device, got %+v", diff)
	}
	if !hasDeviceChange(diff, ChangeRemoved, "192.168.1.11") {
		t.Fatalf("expected removed device, got %+v", diff)
	}
	if !hasDeviceChange(diff, ChangeNew, "192.168.1.12") {
		t.Fatalf("expected new device, got %+v", diff)
	}
}

func TestDiffSubdomainsReportsStatusAndTechnologyChanges(t *testing.T) {
	previous := []SubdomainSnapshot{{Subdomain: "api.example.com", IP: "192.0.2.10", StatusCode: 200, TechGuess: "nginx"}}
	current := []SubdomainSnapshot{{Subdomain: "api.example.com", IP: "192.0.2.10", StatusCode: 403, TechGuess: "cloudflare"}}

	diff := DiffSubdomains(previous, current)
	if len(diff) != 1 || diff[0].Kind != ChangeChanged || diff[0].Subdomain != "api.example.com" {
		t.Fatalf("expected one changed subdomain, got %+v", diff)
	}
}

func TestOpenAndMigrateCreatesVersionedSchema(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	var version int
	if err := db.sql.QueryRowContext(context.Background(), `SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", CurrentSchemaVersion, version)
	}
}

func TestSaveScanUsesTransactionAndCanBeReadBack(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}

	scanID, err := db.SaveScan(context.Background(), ScanRecord{Target: "example.com", ScanType: "web", StartedAt: "2026-08-15T00:00:00Z", CompletedAt: "2026-08-15T00:01:00Z"}, nil, []SubdomainRecord{{Domain: "example.com", Subdomain: "api.example.com", IP: "192.0.2.10", StatusCode: 200, TechGuess: "nginx"}})
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatalf("query saved subdomains: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one saved subdomain, got %d", count)
	}
}

func hasDeviceChange(changes []DeviceChange, kind ChangeKind, ip string) bool {
	for _, change := range changes {
		if change.Kind == kind && change.IP == ip {
			return true
		}
	}
	return false
}

var _ *sql.DB

func TestDiffDevicesIgnoresNonPortMetadataChanges(t *testing.T) {
	previous := []DeviceSnapshot{{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:10", OpenPortsJSON: `[80]`, Confidence: "low"}}
	current := []DeviceSnapshot{{IP: "192.168.1.10", MAC: "BB:BB:BB:BB:BB:10", OpenPortsJSON: `[80]`, Confidence: "high"}}

	if diff := DiffDevices(previous, current); len(diff) != 0 {
		t.Fatalf("expected no device diff when open ports are unchanged, got %+v", diff)
	}
}

func TestLatestScansAndSubdomainSnapshotsSupportHistory(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	for _, scan := range []ScanRecord{
		{Target: "example.com", ScanType: "web", StartedAt: "2026-08-15T00:00:00Z", CompletedAt: "2026-08-15T00:01:00Z"},
		{Target: "example.com", ScanType: "web", StartedAt: "2026-08-15T01:00:00Z", CompletedAt: "2026-08-15T01:01:00Z"},
	} {
		if _, err := db.SaveScan(context.Background(), scan, nil, []SubdomainRecord{{Domain: "example.com", Subdomain: "api.example.com", StatusCode: 200, TechGuess: "nginx"}}); err != nil {
			t.Fatalf("save scan: %v", err)
		}
	}
	latest, err := db.LatestScans(context.Background(), "example.com", 2)
	if err != nil || len(latest) != 2 {
		t.Fatalf("expected two latest scans, got %v %+v", err, latest)
	}
	rows, err := db.LoadSubdomainSnapshots(context.Background(), latest[0].ID)
	if err != nil || len(rows) != 1 || rows[0].Subdomain != "api.example.com" {
		t.Fatalf("expected one latest subdomain snapshot, got %v %+v", err, rows)
	}
}

func TestOpenRejectsUncontrolledSQLiteURI(t *testing.T) {
	if _, err := Open("file:unsafe.db?mode=memory"); err == nil {
		t.Fatal("expected uncontrolled SQLite URI to be rejected")
	}
	if _, err := Open("/tmp/wraith-safe.db"); err != nil {
		t.Fatalf("expected ordinary path to be accepted: %v", err)
	}
}
