// Package releasetrust implements offline, deterministic release trust checks.
package releasetrust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

const AlgorithmEd25519 = "ed25519"

var (
	ErrInvalidManifest   = errors.New("invalid release manifest")
	ErrInvalidProvenance = errors.New("invalid release provenance")
	ErrInvalidTrustRoot  = errors.New("invalid release trust root")
	ErrInvalidSignature  = errors.New("invalid release signature")
)

type Artifact struct {
	Name, Platform, Architecture, Digest, MediaType string
	Size                                            int64
}
type Manifest struct {
	ReleaseID, Version, Commit string
	Artifacts                  []Artifact
}
type Provenance struct{ Repository, Commit, Version, Workflow, Builder, BuildConfigFingerprint, ArtifactDigest string }
type TrustRoot struct {
	SignerID, Algorithm, PublicKey, Fingerprint string
	Active                                      bool
}
type SignatureEnvelope struct{ Algorithm, SignerID, SignerFingerprint, PayloadDigest, Signature string }
type Policy struct {
	Name                                string
	RequireSignature, RequireProvenance bool
}
type Result struct {
	Valid                                 bool
	Reason, ManifestFingerprint, SignerID string
}

func StrictPolicy() Policy {
	return Policy{Name: "strict", RequireSignature: true, RequireProvenance: true}
}

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	if !safe(manifest.ReleaseID) || !safe(manifest.Version) || !commit(manifest.Commit) || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 64 {
		return nil, ErrInvalidManifest
	}
	items := append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(items, func(i, j int) bool { return identity(items[i]) < identity(items[j]) })
	var b strings.Builder
	b.WriteString("manifest\x00" + manifest.ReleaseID + "\x00" + manifest.Version + "\x00" + manifest.Commit + "\n")
	previous := ""
	for _, a := range items {
		id := identity(a)
		if id == previous || !safe(a.Name) || !safe(a.Platform) || !safe(a.Architecture) || !digest(a.Digest) || a.Size <= 0 || !safe(a.MediaType) {
			return nil, ErrInvalidManifest
		}
		previous = id
		b.WriteString(id + "\x00" + a.Digest + "\x00" + itoa(a.Size) + "\x00" + a.MediaType + "\n")
	}
	return []byte(b.String()), nil
}

func CanonicalProvenance(p Provenance) ([]byte, error) {
	if !safe(p.Repository) || !safe(p.Commit) || !safe(p.Version) || !safe(p.Workflow) || !safe(p.Builder) || !digest(p.BuildConfigFingerprint) || !digest(p.ArtifactDigest) || p.Repository != strings.TrimSpace(p.Repository) || strings.Contains(p.Repository, "://") || secretLike(p.Repository) || secretLike(p.Builder) {
		return nil, ErrInvalidProvenance
	}
	return []byte("provenance\x00" + p.Repository + "\x00" + p.Commit + "\x00" + p.Version + "\x00" + p.Workflow + "\x00" + p.Builder + "\x00" + p.BuildConfigFingerprint + "\x00" + p.ArtifactDigest + "\n"), nil
}

func NewTrustRoot(id string, key ed25519.PublicKey) (TrustRoot, error) {
	if !safe(id) || len(key) != ed25519.PublicKeySize {
		return TrustRoot{}, ErrInvalidTrustRoot
	}
	copyKey := append(ed25519.PublicKey(nil), key...)
	return TrustRoot{SignerID: id, Algorithm: AlgorithmEd25519, PublicKey: hex.EncodeToString(copyKey), Fingerprint: hash(copyKey), Active: true}, nil
}

func Sign(m Manifest, p Provenance, signer string, key ed25519.PrivateKey) (SignatureEnvelope, error) {
	if !safe(signer) || len(key) != ed25519.PrivateKeySize {
		return SignatureEnvelope{}, ErrInvalidSignature
	}
	payload, err := statement(m, p)
	if err != nil {
		return SignatureEnvelope{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	return SignatureEnvelope{Algorithm: AlgorithmEd25519, SignerID: signer, SignerFingerprint: hash(pub), PayloadDigest: hash(payload), Signature: hex.EncodeToString(ed25519.Sign(key, payload))}, nil
}

func Verify(policy Policy, m Manifest, p Provenance, e SignatureEnvelope, roots []TrustRoot) Result {
	manifest, err := CanonicalManifest(m)
	if err != nil {
		return Result{Reason: "invalid_manifest"}
	}
	result := Result{Reason: "verification_failed", ManifestFingerprint: hash(manifest), SignerID: e.SignerID}
	if policy.Name != "strict" || !policy.RequireSignature || !policy.RequireProvenance {
		return result
	}
	prov, err := CanonicalProvenance(p)
	if err != nil {
		return result
	}
	if p.Commit != m.Commit || p.Version != m.Version || !artifactDigestInManifest(m, p.ArtifactDigest) {
		return result
	}
	if e.Algorithm != AlgorithmEd25519 || !safe(e.SignerID) || !digest(e.PayloadDigest) || !digest(e.SignerFingerprint) {
		return result
	}
	payload := append(append([]byte(nil), manifest...), prov...)
	if e.PayloadDigest != hash(payload) {
		return result
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return result
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if !safe(r.SignerID) || r.Algorithm != AlgorithmEd25519 || !digest(r.Fingerprint) || seen[r.SignerID] {
			return result
		}
		seen[r.SignerID] = true
		if r.SignerID == e.SignerID && r.Active && r.Fingerprint == e.SignerFingerprint {
			key, err := hex.DecodeString(r.PublicKey)
			if err == nil && len(key) == ed25519.PublicKeySize && hash(key) == r.Fingerprint && ed25519.Verify(ed25519.PublicKey(key), payload, sig) {
				result.Valid = true
				result.Reason = "verified"
				return result
			}
		}
	}
	return result
}

func statement(m Manifest, p Provenance) ([]byte, error) {
	a, e := CanonicalManifest(m)
	if e != nil {
		return nil, e
	}
	b, e := CanonicalProvenance(p)
	if e != nil {
		return nil, e
	}
	return append(a, b...), nil
}
func artifactDigestInManifest(m Manifest, d string) bool {
	for _, a := range m.Artifacts {
		if a.Digest == d {
			return true
		}
	}
	return false
}
func identity(a Artifact) string { return a.Name + "/" + a.Platform + "/" + a.Architecture }
func hash(v []byte) string       { s := sha256.Sum256(v); return hex.EncodeToString(s[:]) }
func digest(v string) bool {
	if len(v) != 64 || v != strings.ToLower(v) {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func commit(v string) bool { return len(v) == 40 && digest(v+strings.Repeat("0", 24)) }
func safe(v string) bool {
	return v != "" && len(v) <= 256 && v == strings.TrimSpace(v) && !strings.ContainsAny(v, "\x00\r\n\\") && !strings.Contains(v, "..") && !secretLike(v)
}
func secretLike(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "bearer ") || strings.Contains(l, "token=") || strings.Contains(l, "password") || strings.Contains(l, "private key") || strings.Contains(l, "@")
}
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	n := v
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}
