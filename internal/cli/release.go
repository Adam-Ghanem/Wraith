package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/releasetrust"
)

const releaseUsage = "usage: wraith release inspect --manifest FILE | release fingerprint --manifest FILE | release policy list | release trust-root list --roots FILE | release verify ARTIFACT --manifest FILE --provenance FILE --signature FILE --roots FILE"

func runRelease(_ context.Context, args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "release" {
		return errors.New(releaseUsage)
	}
	switch args[1] {
	case "policy":
		if len(args) != 3 || args[2] != "list" {
			return errors.New(releaseUsage)
		}
		_, err := fmt.Fprintln(stdout, "policy=strict requires=manifest,digest,provenance,ed25519-signature,explicit-trust-root offline_only=true")
		return err
	case "inspect", "fingerprint":
		return runReleaseManifest(args, stdout, args[1] == "fingerprint")
	case "trust-root":
		return runReleaseRoots(args, stdout)
	case "verify":
		return runReleaseVerify(args, stdout)
	default:
		return errors.New(releaseUsage)
	}
}

func runReleaseManifest(args []string, stdout io.Writer, fingerprintOnly bool) error {
	fs := flag.NewFlagSet("release manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("manifest", "", "manifest file")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return errors.New(releaseUsage)
	}
	var manifest releasetrust.Manifest
	if err := releaseJSON(*path, &manifest); err != nil {
		return errors.New("invalid manifest")
	}
	canonical, err := releasetrust.CanonicalManifest(manifest)
	if err != nil {
		return errors.New("invalid manifest")
	}
	if fingerprintOnly {
		_, err = fmt.Fprintf(stdout, "manifest_fingerprint=%x\n", sha256sum(canonical))
		return err
	}
	_, err = fmt.Fprintf(stdout, "release=%s version=%s commit=%s artifacts=%d manifest_fingerprint=%x\n", manifest.ReleaseID, manifest.Version, manifest.Commit, len(manifest.Artifacts), sha256sum(canonical))
	return err
}

func runReleaseRoots(args []string, stdout io.Writer) error {
	if len(args) < 3 || args[2] != "list" {
		return errors.New(releaseUsage)
	}
	fs := flag.NewFlagSet("release trust-root list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("roots", "", "trust root file")
	if err := fs.Parse(args[3:]); err != nil || fs.NArg() != 0 {
		return errors.New(releaseUsage)
	}
	var roots []releasetrust.TrustRoot
	if err := releaseJSON(*path, &roots); err != nil {
		return errors.New("invalid trust roots")
	}
	for _, r := range roots {
		if _, err := fmt.Fprintf(stdout, "signer=%s algorithm=%s fingerprint=%s active=%t\n", r.SignerID, r.Algorithm, r.Fingerprint, r.Active); err != nil {
			return err
		}
	}
	return nil
}

func runReleaseVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "manifest")
	provenancePath := fs.String("provenance", "", "provenance")
	signaturePath := fs.String("signature", "", "signature")
	rootsPath := fs.String("roots", "", "trust roots")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 1 {
		return errors.New(releaseUsage)
	}
	artifactPath := fs.Arg(0)
	var manifest releasetrust.Manifest
	var provenance releasetrust.Provenance
	var signature releasetrust.SignatureEnvelope
	var roots []releasetrust.TrustRoot
	if releaseJSON(*manifestPath, &manifest) != nil || releaseJSON(*provenancePath, &provenance) != nil || releaseJSON(*signaturePath, &signature) != nil || releaseJSON(*rootsPath, &roots) != nil {
		return errors.New("invalid release metadata")
	}
	var artifact *releasetrust.Artifact
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Name == filepath.Base(artifactPath) {
			artifact = &manifest.Artifacts[i]
			break
		}
	}
	if artifact == nil {
		return errors.New("artifact is not in manifest")
	}
	if err := releasetrust.VerifyArtifactFile(artifactPath, *artifact); err != nil {
		return err
	}
	result := releasetrust.Verify(releasetrust.StrictPolicy(), manifest, provenance, signature, roots)
	_, _ = fmt.Fprintf(stdout, "valid=%t reason=%s signer=%s manifest_fingerprint=%s policy=strict\n", result.Valid, result.Reason, result.SignerID, result.ManifestFingerprint)
	if !result.Valid {
		return errors.New("release verification failed")
	}
	return nil
}

func releaseJSON(path string, destination any) error {
	if strings.TrimSpace(path) == "" || filepath.Clean(path) != path {
		return errors.New("invalid metadata path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("invalid metadata file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing metadata")
		}
		return errors.New("invalid trailing metadata")
	}
	return nil
}

func sha256sum(value []byte) [32]byte { return sha256.Sum256(value) }
