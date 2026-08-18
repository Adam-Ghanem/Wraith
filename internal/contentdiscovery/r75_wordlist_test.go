package contentdiscovery

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadR75WordlistNormalizesLocalEntriesWithinBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "content.txt")
	if err := os.WriteFile(path, []byte("admin\n/api\nadmin\nhttps://outside.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadR75Wordlist(path, R75WordlistLimits{MaxFileBytes: 1024, MaxEntries: 4, MaxEntryBytes: 128})
	if err != nil || !reflect.DeepEqual(entries, []string{"/admin", "/api"}) {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
}

func TestLoadR75WordlistRejectsOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.txt")
	if err := os.WriteFile(path, []byte("/"+string(make([]byte, 64))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadR75Wordlist(path, R75WordlistLimits{MaxFileBytes: 1024, MaxEntries: 4, MaxEntryBytes: 16})
	if !errors.Is(err, ErrR75WordlistLimit) {
		t.Fatalf("err=%v", err)
	}
}
