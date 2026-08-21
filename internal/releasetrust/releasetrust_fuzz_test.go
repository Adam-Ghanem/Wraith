package releasetrust

import "testing"

func FuzzCanonicalManifest(f *testing.F) {
	f.Add("release", "v1.0.0", "0123456789abcdef0123456789abcdef01234567", "artifact", "linux", "amd64", digestA)
	f.Fuzz(func(t *testing.T, release, version, commitID, name, platform, architecture, digestValue string) {
		_, _ = CanonicalManifest(Manifest{ReleaseID: release, Version: version, Commit: commitID, Artifacts: []Artifact{{Name: name, Platform: platform, Architecture: architecture, Digest: digestValue, Size: 1, MediaType: "application/octet-stream"}}})
	})
}

func FuzzCanonicalProvenance(f *testing.F) {
	f.Add("github.com/Adam-Ghanem/Wraith", "0123456789abcdef0123456789abcdef01234567", "v1.0.0", "release", "builder", digestA, digestB)
	f.Fuzz(func(t *testing.T, repository, commitID, version, workflow, builder, configDigest, artifactDigest string) {
		_, _ = CanonicalProvenance(Provenance{Repository: repository, Commit: commitID, Version: version, Workflow: workflow, Builder: builder, BuildConfigFingerprint: configDigest, ArtifactDigest: artifactDigest})
	})
}
