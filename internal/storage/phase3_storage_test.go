package storage

import (
	"context"
	"testing"
)

func TestPhase3MigrationAndFindingPersistence(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	if version := db.CurrentSchemaVersion(context.Background()); version != 3 {
		t.Fatalf("schema version=%d, want 3", version)
	}
	scanID, err := db.SaveScanWithFindings(context.Background(), ScanRecord{Target: "example.com", ScanType: "phase3", StartedAt: "2026-08-15T00:00:00Z", CompletedAt: "2026-08-15T00:01:00Z"}, nil, nil, []ContentFindingRecord{{Subdomain: "app.example.com", Path: "/admin", StatusCode: 403, ResponseLength: 12, DiscoveredAt: "2026-08-15T00:00:00Z"}}, []JSFindingRecord{{Subdomain: "app.example.com", SourceFile: "https://app.example.com/app.js", FindingType: "secret", Value: "abcd…mnop", Confidence: "potential", DiscoveredAt: "2026-08-15T00:00:00Z"}})
	if err != nil {
		t.Fatalf("save findings: %v", err)
	}
	content, err := db.LoadContentFindings(context.Background(), scanID)
	if err != nil || len(content) != 1 || content[0].Path != "/admin" {
		t.Fatalf("content findings=%v %+v", err, content)
	}
	js, err := db.LoadJSFindings(context.Background(), scanID)
	if err != nil || len(js) != 1 || js[0].Confidence != "potential" {
		t.Fatalf("JS findings=%v %+v", err, js)
	}
}

func TestPhase3DiffsReportOnlyNewFindings(t *testing.T) {
	content := DiffContentFindings(
		[]ContentFindingSnapshot{{Subdomain: "app.example.com", Path: "/admin", StatusCode: 403, ResponseLength: 12}},
		[]ContentFindingSnapshot{{Subdomain: "app.example.com", Path: "/admin", StatusCode: 200, ResponseLength: 20}, {Subdomain: "app.example.com", Path: "/backup", StatusCode: 301, ResponseLength: 0}},
	)
	if len(content) != 1 || content[0].Kind != ChangeNew || content[0].Current.Path != "/backup" {
		t.Fatalf("content diff=%+v", content)
	}
	js := DiffJSFindings(
		[]JSFindingSnapshot{{Subdomain: "app.example.com", SourceFile: "app.js", FindingType: "endpoint", Value: "/api/users", Confidence: "observed"}},
		[]JSFindingSnapshot{{Subdomain: "app.example.com", SourceFile: "app.js", FindingType: "endpoint", Value: "/api/users", Confidence: "observed"}, {Subdomain: "app.example.com", SourceFile: "app.js", FindingType: "secret", Value: "abcd…mnop", Confidence: "potential"}},
	)
	if len(js) != 1 || js[0].Kind != ChangeNew || js[0].Current.Value != "abcd…mnop" {
		t.Fatalf("JS diff=%+v", js)
	}
}

func TestPhase3StorageRejectsUnredactedSecrets(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	_, err = db.SaveScanWithFindings(context.Background(), ScanRecord{Target: "example.com", ScanType: "phase3", StartedAt: "start", CompletedAt: "end"}, nil, nil, nil, []JSFindingRecord{{Subdomain: "app.example.com", SourceFile: "app.js", FindingType: "secret", Value: "AKIA1234567890ABCDEF", Confidence: "potential"}})
	if err == nil {
		t.Fatal("expected unredacted secret to be rejected")
	}
}
