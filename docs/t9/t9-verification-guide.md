# T9 Offline Verification Guide

T9 verification is local and offline. An operator must explicitly provide the artifact, manifest, provenance statement, signature envelope, and local trust-root configuration. T9 does not discover keys, contact GitHub, resolve DNS, download files, invoke a package manager, or publish releases.

```sh
wraith release policy list
wraith release inspect --manifest manifest.json
wraith release fingerprint --manifest manifest.json
wraith release trust-root list --roots trusted-roots.json
wraith release verify ./wraith-linux-amd64 \
  --manifest manifest.json \
  --provenance provenance.json \
  --signature signature.json \
  --roots trusted-roots.json
```

Strict verification requires an exact local artifact digest, a canonical manifest, a provenance statement bound to the same release version, source revision, and artifact digest, an `ed25519` signature over the canonical statement, and one explicitly trusted active signer. A missing, malformed, substituted, duplicated, unsupported, or untrusted value fails verification.

T9 has no signing command. Private signing keys must remain outside Wraith and outside the project database. Test signatures use ephemeral in-memory keys only.
