# T3 Local Data Classification and Handling

## Classification

| Class | Examples | Storage/output rule |
|---|---|---|
| Public | CLI usage text, static build metadata, package versions | May be committed and rendered. |
| Internal | Project IDs, scope versions, authorization IDs, bounded reason codes | Store only project-scoped records; do not treat as public telemetry. |
| Security-sensitive | Audit events, evidence references, findings, target metadata | Preserve project isolation, canonical fingerprints, bounded output, and explicit local access controls. |
| Secret-forbidden | Passwords, bearer tokens, cookies, private keys, credential-bearing URLs | Reject at T3 trust/audit boundaries; never persist, render, or include in event reason codes. |

## Encryption and filesystem responsibility

Wraith does not claim that its SQLite database is encrypted. The owner is responsible for host disk encryption, restrictive directory permissions, backup policy, and key management. T3 keeps this boundary explicit rather than adding unverifiable custom encryption.

The database path remains a filesystem path and rejects SQLite URI parameters. Audit records are project-scoped and fingerprint-validated on read; that protects against accidental cross-project reads and simple tampering, not against an owner or attacker with unrestricted local database write access.

## Output handling

T3 reuses existing safe output-path handling. Authorization audit output contains identifiers, state labels, UTC timestamps, canonical fingerprints, and bounded reason codes only. It does not repeat evidence references, subjects, created-by references, raw targets, credentials, HTTP headers, response bodies, or secret findings.
