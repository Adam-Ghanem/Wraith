package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseJSONRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"ReleaseID":"one"}{"ReleaseID":"two"}`), 0o600); err != nil { t.Fatal(err) }
	var output struct{ ReleaseID string }
	if err := releaseJSON(path, &output); err == nil { t.Fatal("trailing JSON document accepted") }
}
