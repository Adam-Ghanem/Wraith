package storage

import (
	"context"
	"testing"
)

func TestPhase4MigrationPersistenceAndIDs(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	if version := db.CurrentSchemaVersion(ctx); version != 3 {
		t.Fatalf("schema version=%d, want 3", version)
	}
	ports := []PortFindingRecord{{SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Service: "https", Source: "nmap", DiscoveredAt: "end"}}
	vulns := []VulnFindingRecord{{Subdomain: "app.example.com", TemplateID: "fixture-exposure", Severity: "medium", MatchedURL: "https://app.example.com/admin", Description: "fixture", DiscoveredAt: "end"}}
	scanID, err := db.SaveScanWithAllFindings(ctx, ScanRecord{Target: "example.com", ScanType: "phase4", StartedAt: "start", CompletedAt: "end"}, nil, nil, nil, nil, ports, vulns)
	if err != nil {
		t.Fatalf("save Phase 4 findings: %v", err)
	}
	if ports[0].ID == 0 || ports[0].ScanID != scanID || vulns[0].ID == 0 || vulns[0].ScanID != scanID {
		t.Fatalf("in-memory IDs not populated: ports=%+v vulns=%+v scanID=%d", ports, vulns, scanID)
	}
	loadedPorts, err := db.LoadPortFindings(ctx, scanID)
	if err != nil || len(loadedPorts) != 1 || loadedPorts[0].ID == 0 || loadedPorts[0].ScanID != scanID || loadedPorts[0].Source != "nmap" {
		t.Fatalf("port findings=%v %+v", err, loadedPorts)
	}
	loadedVulns, err := db.LoadVulnFindings(ctx, scanID)
	if err != nil || len(loadedVulns) != 1 || loadedVulns[0].ID == 0 || loadedVulns[0].ScanID != scanID || loadedVulns[0].Severity != "medium" {
		t.Fatalf("vulnerability findings=%v %+v", err, loadedVulns)
	}
}

func TestPhase4RejectsInvalidPortSource(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	_, err = db.SaveScanWithAllFindings(ctx, ScanRecord{Target: "example.com", ScanType: "phase4", StartedAt: "start", CompletedAt: "end"}, nil, nil, nil, nil, []PortFindingRecord{{SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Source: "other"}}, nil)
	if err == nil {
		t.Fatal("expected invalid source rejection")
	}
}

func TestPhase4DiffsReportOnlyNewFindings(t *testing.T) {
	ports := DiffPortFindings(
		[]PortFindingSnapshot{{SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Service: "https", Source: "nmap"}},
		[]PortFindingSnapshot{{SubdomainOrIP: "app.example.com", Port: 443, Protocol: "tcp", Service: "changed", Source: "nmap"}, {SubdomainOrIP: "app.example.com", Port: 8443, Protocol: "tcp", Service: "https-alt", Source: "nmap"}},
	)
	if len(ports) != 1 || ports[0].Kind != ChangeNew || ports[0].Current.Port != 8443 {
		t.Fatalf("port diff=%+v", ports)
	}
	vulns := DiffVulnFindings(
		[]VulnFindingSnapshot{{Subdomain: "app.example.com", TemplateID: "fixture-exposure", Severity: "low", MatchedURL: "https://app.example.com/a"}},
		[]VulnFindingSnapshot{{Subdomain: "app.example.com", TemplateID: "fixture-exposure", Severity: "high", MatchedURL: "https://app.example.com/a"}, {Subdomain: "app.example.com", TemplateID: "fixture-cve", Severity: "high", MatchedURL: "https://app.example.com/b"}},
	)
	if len(vulns) != 1 || vulns[0].Kind != ChangeNew || vulns[0].Current.TemplateID != "fixture-cve" {
		t.Fatalf("vulnerability diff=%+v", vulns)
	}
}

func TestPhase4MigrationUpgradesSchemaVersion2(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	if _, err := db.sql.ExecContext(ctx, `DROP TABLE port_findings; DROP TABLE vuln_findings; DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatalf("simulate schema version 2: %v", err)
	}
	if version := db.CurrentSchemaVersion(ctx); version != 2 {
		t.Fatalf("simulated schema version=%d, want 2", version)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migration: %v", err)
	}
	if version := db.CurrentSchemaVersion(ctx); version != 3 {
		t.Fatalf("upgraded schema version=%d, want 3", version)
	}
	if _, err := db.LoadPortFindings(ctx, 1); err != nil {
		t.Fatalf("port findings table after upgrade: %v", err)
	}
	if _, err := db.LoadVulnFindings(ctx, 1); err != nil {
		t.Fatalf("vulnerability findings table after upgrade: %v", err)
	}
}
