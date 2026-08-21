package releasetrust

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxArtifactBytes int64 = 1 << 30

// VerifyArtifactFile validates one explicitly selected regular local file. It
// performs no discovery, download, subprocess invocation, or symlink follow.
func VerifyArtifactFile(path string, artifact Artifact) error {
	if _, err := CanonicalManifest(Manifest{ReleaseID: "verification", Version: "v1", Commit: "0123456789abcdef0123456789abcdef01234567", Artifacts: []Artifact{artifact}}); err != nil {
		return ErrInvalidManifest
	}
	if filepath.Base(path) != artifact.Name || filepath.Clean(path) != path {
		return errors.New("artifact path identity mismatch")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxArtifactBytes || info.Size() != artifact.Size {
		return errors.New("artifact file rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("artifact file rejected")
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, maxArtifactBytes+1)); err != nil {
		return fmt.Errorf("hash artifact: %w", err)
	}
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != artifact.Digest {
		return errors.New("artifact digest mismatch")
	}
	return nil
}
