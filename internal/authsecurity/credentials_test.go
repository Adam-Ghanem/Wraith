package authsecurity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredentialInputDeduplicatesBoundedLocalPairs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.txt")
	if err := os.WriteFile(path, []byte("demo-user:opaque-local-value\ndemo-user:opaque-local-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pairs, err := LoadCredentialInput(CredentialInput{CredentialsPath: path}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].ID == "" || pairs[0].username != "demo-user" || pairs[0].password != "opaque-local-value" {
		t.Fatalf("credential metadata invalid")
	}
}

func TestLoadCredentialInputRejectsOversizedLocalSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", MaxCredentialFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialInput(CredentialInput{CredentialsPath: path}, 1); err == nil {
		t.Fatal("expected oversized credential source rejection")
	}
}
