package releasetrust

import "testing"

func BenchmarkCanonicalManifest(b *testing.B) {
	m := Manifest{ReleaseID: "wraith-v1", Version: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", Artifacts: []Artifact{{Name: "wraith-linux-amd64", Platform: "linux", Architecture: "amd64", Digest: digestA, Size: 42, MediaType: "application/octet-stream"}}}
	for i := 0; i < b.N; i++ {
		_, _ = CanonicalManifest(m)
	}
}

func BenchmarkVerifyStrict(b *testing.B) {
	// Verification complexity is O(number of trust roots + manifest artifacts).
	for i := 0; i < b.N; i++ {
		_, _ = CanonicalProvenance(Provenance{Repository: "github.com/Adam-Ghanem/Wraith", Commit: "0123456789abcdef0123456789abcdef01234567", Version: "v1.0.0", Workflow: "release", Builder: "builder", BuildConfigFingerprint: digestA, ArtifactDigest: digestB})
	}
}
