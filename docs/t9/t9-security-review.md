# T9 Security Review

T9 replaces neither the existing checksum helper nor any existing execution, trust, governance, or data-protection authority. Its new trust decision is local and fail-closed.

| Abuse case | Control |
|---|---|
| Artifact substitution or truncation | Bounded streaming SHA-256, exact size check, exact basename/manifest identity check, and manifest-bound digest. |
| Manifest or provenance tampering | Explicit canonical byte encoding and signature payload digest binding. |
| Signer or algorithm substitution | Only `ed25519` is accepted; signer identity, root fingerprint, public key, and signature must all agree. |
| Duplicate ambiguity | Duplicate artifact identity and duplicate root identifiers reject verification. |
| Secret-bearing metadata | Safe bounded fields reject credential markers, URL credentials, key material, token-like fields, control characters, and traversal-like values. |
| Remote-key or update abuse | The T9 core and CLI have no network, DNS, subprocess, key retrieval, download, scheduler, or publisher path. |

Private signing material is never read by T9 production code, written to SQLite, placed in metadata, or logged. Tests generate ephemeral keys in memory only.
