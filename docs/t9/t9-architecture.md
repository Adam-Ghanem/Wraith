# T9 Architecture: Offline Release Trust

## Purpose and boundaries

T9 closes the gap in the prior checksum-only release process. It establishes a **local, deterministic, fail-closed** trust decision for a concrete artifact without contacting a network service or persisting private key material. It is not a signing service, package registry, update engine, deployment system, certificate authority, or key-management service.

The implementation is centered on `internal/releasetrust`, a pure package. It consumes T7 safe-metadata screening and T8 protection boundaries for release metadata; it does not recreate their policies. T1/T2 authorization, T3/T4 execution trust, R3 transport, and T5/T6 egress ownership are unchanged: release verification has no transport or egress path.

## Trust chain

```text
local artifact bytes
  -> SHA-256 digest
  -> canonical manifest artifact entry
  -> canonical provenance bound to the same release/artifact digest
  -> canonical signed release statement
  -> Ed25519 signature envelope
  -> explicitly supplied local trust root
  -> strict verification result
```

The verifier never treats a signature's existence as trust. Strict trust requires a recognized algorithm, one non-duplicated active trust root, matching signer identity and fingerprint, a signature over the canonical release statement, exact artifact identity and digest, and provenance bound to the same repository, revision, release version, and artifact digest.

## Canonical contracts

T9 accepts only bounded typed fields. Identifiers are ASCII-safe, normalized once, and reject leading/trailing whitespace, control characters, path separators, secret-like content, credential-bearing URLs, duplicate artifacts, duplicate trust roots, unsupported algorithms, and ambiguous digests. Canonical payloads are explicit field-order byte sequences, not arbitrary JSON.

The only supported signature algorithm is `ed25519`. Algorithm labels are normalized and compared before public-key parsing or signature verification. SHA-256 hex digests are lowercase and exactly 64 characters. The manifest artifacts are sorted by a digest-bound identity tuple of name, version, platform, and architecture.

## Metadata and provenance

The manifest binds release ID, version, source revision, and ordered artifact entries. The provenance binds repository identity, revision, release version, workflow identity, builder identity, build-configuration fingerprint, and the same artifact digest. It contains no arbitrary environment dump, private key, password, token, API key, bearer value, or credential-bearing URL.

The signed statement is the canonical manifest plus canonical provenance fingerprint. Any change to either artifact metadata or provenance invalidates the signature verification result.

## Local file safety

Artifact verification reads a single explicitly supplied regular file via a bounded streaming SHA-256 reader. It rejects empty files, directories, symlinks, oversized inputs, path traversal-like manifest names, and an identity mismatch between requested artifact basename and its manifest entry. No metadata input causes file-system discovery, remote retrieval, or a subprocess execution.

## Policy

`strict` is the default and only production-trust policy. It requires the full chain. `local-development` is an explicitly labeled diagnostic policy which may be used to inspect canonical metadata but never returns a production-trusted result. Policy names cannot silently downgrade a strict request.

## Test-first acceptance criteria

The implementation must first prove red-state tests for deterministic canonicalization, duplicate rejection, signature and signer substitution, provenance substitution, altered artifact data, malformed/oversized local inputs, path safety, and secret-bearing metadata. Integration tests must use ephemeral Ed25519 keys generated in memory; no key fixture is committed. Fuzz targets are bounded, local, and parser-only.
