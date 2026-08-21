package releasetrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCanonicalManifestIsDeterministicAndRejectsDuplicateArtifactIdentity(t *testing.T) {
	manifest := Manifest{ReleaseID: "wraith-v1", Version: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", Artifacts: []Artifact{{Name: "wraith-linux-amd64", Platform: "linux", Architecture: "amd64", Digest: digestA, Size: 42, MediaType: "application/octet-stream"}, {Name: "wraith-darwin-arm64", Platform: "darwin", Architecture: "arm64", Digest: digestB, Size: 43, MediaType: "application/octet-stream"}}}
	first, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[0], manifest.Artifacts[1] = manifest.Artifacts[1], manifest.Artifacts[0]
	second, err := CanonicalManifest(manifest)
	if err != nil || string(first) != string(second) {
		t.Fatalf("canonical determinism err=%v", err)
	}
	manifest.Artifacts = append(manifest.Artifacts, manifest.Artifacts[0])
	if _, err := CanonicalManifest(manifest); err == nil {
		t.Fatal("duplicate artifact identity was accepted")
	}
}

func TestVerifyFailsClosedOnSignerAndProvenanceSubstitution(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{ReleaseID: "wraith-v1", Version: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", Artifacts: []Artifact{{Name: "wraith-linux-amd64", Platform: "linux", Architecture: "amd64", Digest: digestA, Size: 42, MediaType: "application/octet-stream"}}}
	provenance := Provenance{Repository: "github.com/Adam-Ghanem/Wraith", Commit: manifest.Commit, Version: manifest.Version, Workflow: "release", Builder: "github-actions", BuildConfigFingerprint: digestB, ArtifactDigest: digestA}
	root, err := NewTrustRoot("wraith-release", public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(manifest, provenance, "wraith-release", private)
	if err != nil {
		t.Fatal(err)
	}
	if result := Verify(StrictPolicy(), manifest, provenance, envelope, []TrustRoot{root}); !result.Valid {
		t.Fatalf("valid release rejected: %s", result.Reason)
	}
	envelope.SignerID = "substituted"
	if result := Verify(StrictPolicy(), manifest, provenance, envelope, []TrustRoot{root}); result.Valid {
		t.Fatal("signer substitution accepted")
	}
	envelope, _ = Sign(manifest, provenance, "wraith-release", private)
	provenance.Commit = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	if result := Verify(StrictPolicy(), manifest, provenance, envelope, []TrustRoot{root}); result.Valid {
		t.Fatal("provenance substitution accepted")
	}
}

func TestProvenanceRejectsSecretLikeMetadata(t *testing.T) {
	_, err := CanonicalProvenance(Provenance{Repository: "https://user:password@example.invalid/repo", Commit: "0123456789abcdef0123456789abcdef01234567", Version: "v1.0.0", Workflow: "release", Builder: "token=secret", BuildConfigFingerprint: digestA, ArtifactDigest: digestB})
	if err == nil {
		t.Fatal("credential-bearing provenance accepted")
	}
}

const digestA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const digestB = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
