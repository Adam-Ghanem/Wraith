package cli

import (
	"bytes"
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
