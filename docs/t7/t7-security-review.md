# T7 Security Review

## Review Scope

T7 introduces a pure representation-governance layer only. The review covered secret detection, URL handling, structured-data bounds, immutable evidence validation, finding persistence, report rendering, audit event integrity, CLI input/output, migration compatibility, and the inherited T6 fixture-export denial.

| Threat | Control | Fail-closed result |
|---|---|---|
| Credential-bearing URL reaches identity, report, audit, or storage | Userinfo is rejected; sensitive query values are redacted in safe URL projections; safe references reject raw credential material | No raw credential URL is retained. |
| Secret header, cookie, or API key reaches evidence | Header values are governed before evidence payload serialization and fingerprinting | Stored payload carries `REDACTED`, explicit classification, and policy version. |
| Unsafe structured JSON bypasses field-level checks | Bounded recursive sanitizer enforces depth, keys, array size, bytes, and string length | Oversized, malformed, or unsafe structures are rejected or redacted deterministically. |
| Forged classification/fingerprint record is persisted | Data is re-sanitized before immutable identifier validation; T7 policy version and classification are checked | Unsafe or forged observation metadata is rejected. |
| Finding description or factor leaks a credential | R11.5 persistence validates descriptive fields, evidence references, and JSON factors with T7 | The write is rejected before risk state is stored. |
| Caller bypasses report construction and calls renderer directly | Renderers reconstruct and compare the canonical R16 snapshot before every format | Terminal, JSON, Markdown, and offline HTML reject forged unsafe snapshots. |
| Required governance audit write fails | Evidence insert and its audit event share one SQLite transaction | Evidence persistence is rolled back. |
| Legacy fixture export invokes direct scan/history code | T6 root gate classifies `export-fixtures` as provider outbound and denies it before handler dispatch | No new egress or unclassified export path is enabled. |

## Explicit Non-Claims

T7 is not a vault, encryption system, credential store, egress gateway, authorization system, scope engine, transport, resolver, socket implementation, scanner, exploit framework, worker, scheduler, telemetry pipeline, remote service, or automatic remediation capability. It does not claim that redacted data is harmless in every downstream context; it ensures only that the repository’s governed representation never contains the detected raw secret material.

## Residual Limitations

Detection is semantic and marker-based rather than entropy-based; therefore T7 intentionally does not attempt to infer every possible proprietary secret format. It preserves existing strict secret-safe upstream constructors and adds bounded validation at key persistence/output boundaries. Legacy records remain readable under their explicit `legacy` policy marker; T7 does not silently rewrite historical evidence.
