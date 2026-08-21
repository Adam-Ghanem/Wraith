package releasetrust

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyArtifactRejectsModifiedAndPathMismatchedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wraith-linux-amd64")
	bytes := []byte("trusted artifact")
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	artifact := Artifact{Name: "wraith-linux-amd64", Platform: "linux", Architecture: "amd64", Digest: hex.EncodeToString(sum[:]), Size: int64(len(bytes)), MediaType: "application/octet-stream"}
	if err := VerifyArtifactFile(path, artifact); err != nil {
		t.Fatalf("valid artifact: %v", err)
	}
	if err := os.WriteFile(path, append(bytes, '!'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactFile(path, artifact); err == nil {
		t.Fatal("modified artifact accepted")
	}
	if err := VerifyArtifactFile(filepath.Join(dir, "other"), artifact); err == nil {
		t.Fatal("mismatched path accepted")
	}
}
