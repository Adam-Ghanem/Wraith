package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPhase3ScanOutputIncludesContentAndJSFindings(t *testing.T) {
	var jsonOutput bytes.Buffer
	err := renderScanOutput(&jsonOutput, true, scanOutput{
		ScanID:          1,
		Target:          "example.com",
		ContentFindings: []storage.ContentFindingRecord{{Subdomain: "app.example.com", Path: "/admin", StatusCode: 403}},
		JSFindings:      []storage.JSFindingRecord{{Subdomain: "app.example.com", FindingType: "secret", Value: "abcd…mnop", Confidence: "potential"}},
	})
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if _, ok := decoded["content_findings"]; !ok {
		t.Fatalf("content_findings missing from %s", jsonOutput.String())
	}
	if _, ok := decoded["js_findings"]; !ok {
		t.Fatalf("js_findings missing from %s", jsonOutput.String())
	}
}

func TestPhase3HistoryOutputIncludesNewFindingSections(t *testing.T) {
	var terminal bytes.Buffer
	err := renderHistoryOutput(&terminal, false, historyOutput{
		ContentChanges: []storage.ContentFindingChange{{Kind: storage.ChangeNew, Current: storage.ContentFindingSnapshot{Subdomain: "app.example.com", Path: "/admin", StatusCode: 403}}},
		JSChanges:      []storage.JSFindingChange{{Kind: storage.ChangeNew, Current: storage.JSFindingSnapshot{Subdomain: "app.example.com", SourceFile: "app.js", FindingType: "endpoint", Value: "/api/users", Confidence: "observed"}}},
	})
	if err != nil {
		t.Fatalf("render history: %v", err)
	}
	for _, expected := range []string{"NEW CONTENT FINDINGS", "/admin", "NEW JS FINDINGS", "/api/users"} {
		if !strings.Contains(terminal.String(), expected) {
			t.Fatalf("history output missing %q: %s", expected, terminal.String())
		}
	}
}

func TestPhase3ScanOutputIncludesPersistedRecordIDs(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate storage: %v", err)
	}
	subdomains := []storage.SubdomainRecord{{Domain: "example.com", Subdomain: "app.example.com", StatusCode: 200, FirstSeen: "start", LastSeen: "end"}}
	contentFindings := []storage.ContentFindingRecord{{Subdomain: "app.example.com", Path: "/robots.txt", StatusCode: 200, ResponseLength: 12, DiscoveredAt: "end"}}
	scanID, err := db.SaveScanWithFindings(context.Background(), storage.ScanRecord{Target: "example.com", ScanType: "web", StartedAt: "start", CompletedAt: "end"}, nil, subdomains, contentFindings, nil)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	var output bytes.Buffer
	if err := renderScanOutput(&output, true, scanOutput{ScanID: scanID, Target: "example.com", Subdomains: subdomains, ContentFindings: contentFindings}); err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var decoded scanOutput
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(decoded.Subdomains) != 1 || decoded.Subdomains[0].ID == 0 || decoded.Subdomains[0].ScanID != scanID {
		t.Fatalf("subdomain IDs not preserved: %+v, scanID=%d", decoded.Subdomains, scanID)
	}
	if len(decoded.ContentFindings) != 1 || decoded.ContentFindings[0].ID == 0 || decoded.ContentFindings[0].ScanID != scanID {
		t.Fatalf("content finding IDs not preserved: %+v, scanID=%d", decoded.ContentFindings, scanID)
	}
}
