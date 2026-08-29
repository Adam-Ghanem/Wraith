package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStripStandaloneInputList(t *testing.T) {
	clean, path, err := stripStandaloneInputList([]string{"scan", "-sV", "-iL", "targets.txt", "-p", "22,80"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "targets.txt" {
		t.Fatalf("path=%q, want targets.txt", path)
	}
	want := []string{"scan", "-sV", "-p", "22,80"}
	if !reflect.DeepEqual(clean, want) {
		t.Fatalf("clean=%v, want %v", clean, want)
	}
}

func TestLoadStandaloneTargetListDeduplicatesAndExpandsCIDR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "# inventory\n192.0.2.1\nexample.com\n192.0.2.0/31\n192.0.2.1\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := loadStandaloneTargetList(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tcp://192.0.2.1/",
		"tcp://example.com/",
		"tcp://192.0.2.0/",
	}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets=%v, want %v", targets, want)
	}
}

func TestStripStandaloneInputListRejectsMultipleLists(t *testing.T) {
	if _, _, err := stripStandaloneInputList([]string{"scan", "-iL", "a.txt", "--input-list", "b.txt"}); err == nil {
		t.Fatal("expected multiple input lists to fail")
	}
}

func TestLoadStandaloneTargetListRejectsInvalidTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("https://example.com/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStandaloneTargetList(path); err == nil {
		t.Fatal("expected URL target to be rejected")
	}
}
