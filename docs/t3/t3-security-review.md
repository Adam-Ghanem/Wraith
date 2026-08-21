# T3 Security Review

## Reviewed threats and controls

| Threat | T3 control | Residual boundary |
|---|---|---|
| Operator flag mistaken for authorization proof | Distinct assurance levels and T1/T2 chain validation | Real-world ownership proof remains outside local tooling. |
| Expired/revoked/forged authorization state | Canonical T1 validation and fingerprint checks before T2/T3 decisions | Local DB administrators can still alter files; fingerprints make altered rows fail closed when loaded. |
| Cross-project scope or audit access | Exact project filters, project-bound T1/T2 validation, project-scoped audit event keys | Host-level filesystem access is a deployment responsibility. |
| Active task dispatched after trust changes | Existing authorization rechecks plus T3 pre-dispatch task gate | R3 independently rechecks transport and destination policy. |
| Audit event overwrite or injection | Additive append-only schema, sequence keys, canonical fingerprint validation, secret-like input rejection | Audit records are local evidence, not external attestations. |
| Unreviewed subprocess expansion | No new executor; `executil` remains the only shared process runner with direct executable paths, context cancellation, and output caps | Optional tool availability and host execution rights remain environmental. |
| Transport or DNS bypass | No T3 HTTP/DNS/socket API; R3 remains sole owner | Existing R3 behavior is preserved and independently tested. |
| Release secret leakage | No private key storage; checksum verification is local; high-confidence CI marker check | Owner-managed signing infrastructure is required for signed provenance. |
| Privilege escalation | Existing discovery UX states required Linux capabilities; T3 introduces no sudo, setuid, automatic elevation, or fallback scanner | Operators must grant capabilities only under their own controlled process policy. |

## Egress audit

The T3 trust authority, authorization-audit storage adapter, and authorization CLI have no `net/http`, resolver, dial, socket, `os/exec`, or command-execution dependency. Existing transport behavior remains in `internal/httpengine`; existing optional subprocess behavior remains in `internal/executil` and fixed portscan/vulncheck consumers.

## Explicit non-claims

T3 does not claim cryptographic ownership verification, automatic remediation, vulnerability safety, encrypted SQLite, signed artifacts, cloud provenance, or universal migration of every legacy R1 path. Legacy active paths must keep their explicit R1 validation and do not receive a fail-open T2/T3 fallback.
