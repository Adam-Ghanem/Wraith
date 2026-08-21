# T7 Architecture: Central Data Classification and Evidence Protection

## Authority Boundary

`internal/dataclassification` is a pure deterministic package. It performs classification, redaction, safe URL projection, bounded structured-data sanitization, canonical secret-marker detection, and destination-policy decisions only. It does not perform filesystem, SQLite, HTTP, DNS, socket, subprocess, process, scanner, scheduler, telemetry, or cloud operations.

T7 consumes but does not recreate T1 authorization, T2 scope, T3 assurance/audit, T4 derived trust, T5 outbound policy, T6 adoption enforcement, or R3 transport. It governs only the representation of data that is persisted, audited, passed between components, rendered, exported, or returned to an operator.

## Classification Model

| Ordered level | Meaning | Persistence/report/export default |
|---|---|---|
| `public` | Deliberately non-sensitive structural data | Allow. |
| `internal` | Repository-local operational metadata | Allow with project scope. |
| `sensitive` | Diagnostic data requiring representation redaction | Redact before persistence, report, audit, export, or CLI output. |
| `secret` | Credential or authentication material | Never persist raw; redact a structured value or block an unsafe free-form representation. |
| `restricted` | Material unsafe to retain or disclose even in redacted form | Block. |

The classifier considers kind, field/key name, source, destination, URL structure, semantic markers, and bounded structured location. It does not classify from entropy or length alone. Canonical marker matching is case-insensitive and recognizes at least password/passwd/pwd, secret, token, access/refresh token, API key, authorization, proxy authorization, cookie, session, CSRF/XSRF, client secret, private key, certificate, and credential forms.

## Pure Package Contract

| Function family | Contract |
|---|---|
| Field/value classification | Returns an ordered level, destination action, stable reason code, and whether redaction occurred. |
| URL governance | Rejects credential-bearing userinfo; retains only a safe scheme/host/port/path/query representation with sensitive query values replaced by `[REDACTED]`. |
| Header governance | Retains safe names; redacts authorization, cookie, proxy authorization, API-key-like, session, and CSRF-value material. |
| JSON/form/body governance | Traverses only bounded depth, keys, arrays, bytes, and string lengths; sensitive-key values become `[REDACTED]`; malformed or over-limit structures fail closed. |
| Safe reference validation | Rejects credential-bearing URLs and secret-like free-form values before fingerprints, audit metadata, or cross-component references. |
| Destination policy | Produces only `allow`, `redact`, or `block`; secret/restricted data is never silently downgraded. |

The policy version is an explicit constant. All canonical fingerprints are computed only from governed/redacted representations, never from raw secret values.

## Integration Plan

| Existing seam | T7 change | Preserved behavior |
|---|---|---|
| R2 evidence constructors | Call T7 before canonical payload fingerprinting; expose classification and policy version with existing `Redacted` state. | Evidence kinds, subject identity rules, source semantics, and R8/R17 meaning remain unchanged. |
| R2 evidence persistence | Revalidate governed observation metadata and payload, append a typed safe governance event transactionally, and fail closed if required audit storage is unavailable. | Project isolation and immutable observation insertion remain unchanged. |
| R11.5 finding persistence | Reject unsafe descriptive/factor/reference content before write. | Risk scoring, confidence, severity, and correlation remain authoritative R11.5 behavior. |
| R16 report model/renderers | Replace repeated local secret-marker predicates with T7 validation and validate a snapshot again at renderer entry. | Report projections, executive/technical split, HTML escaping, and output formats remain unchanged. |
| CLI output/export | Apply export policy before file/stdout; retain `0600` output permissions. | Existing output formats and path handling remain unchanged. |
| Legacy `export-fixtures` | Deny at the inherited T6 root gate because it directly invokes legacy scan code and produces unclassified JSON. | No new export behavior or egress capability is added. |
| T3-style audit persistence | Add a separate project-scoped append-only governance audit record containing event type, policy version, safe subject reference, timestamp, fingerprint, and classification only. | T3 authorization audit event schema and authority remain unchanged. |

## Storage Compatibility

Migration `025_t7_data_governance.sql` is additive. It adds governed-observation classification and policy-version metadata plus a separate append-only governance-audit table. Existing rows receive an explicit legacy-safe compatibility policy marker but are never rewritten, reclassified, or granted new authority. New writes use the current T7 policy version.

## Fail-Closed Rules

Unsafe raw data, forged classifications, invalid policy versions, malformed or oversized structured content, cross-project reads, secret-like audit references, unsafe finding text, renderer input that cannot be revalidated, and unavailable required governance audit storage all fail closed. T7 does not provide a production bypass or an “allow all secrets” configuration.
