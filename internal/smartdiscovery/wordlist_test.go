package smartdiscovery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadWordlistUsesExplicitBoundedSafeLocalEntries(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "paths.txt")
	if err := os.WriteFile(filename, []byte("/docs\nopenapi.json\n/docs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := LoadWordlist(filename, WordlistLimits{MaxFileBytes: 1024, MaxEntries: 8, MaxEntryBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if expected := []string{"/docs", "/openapi.json"}; !reflect.DeepEqual(paths, expected) {
		t.Fatalf("paths=%#v expected=%#v", paths, expected)
	}
}

func TestLoadWordlistRejectsSensitiveAndOversizedInput(t *testing.T) {
	directory := t.TempDir()
	sensitive := filepath.Join(directory, "sensitive.txt")
	if err := os.WriteFile(sensitive, []byte("/.env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWordlist(sensitive, WordlistLimits{MaxFileBytes: 1024, MaxEntries: 8, MaxEntryBytes: 64}); err == nil {
		t.Fatal("expected sensitive path rejection")
	}
	overflow := filepath.Join(directory, "large.txt")
	if err := os.WriteFile(overflow, []byte("/"+string(make([]byte, 100))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWordlist(overflow, WordlistLimits{MaxFileBytes: 8, MaxEntries: 8, MaxEntryBytes: 64}); err == nil {
		t.Fatal("expected oversized wordlist rejection")
	}
}
