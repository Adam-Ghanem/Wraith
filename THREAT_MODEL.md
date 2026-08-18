# Wraith CLI-First Toolkit Threat Model

**Status:** Architecture threat model for the proposed CLI-first Web and API toolkit evolution. It complements the implemented-feature model in [`docs/threat-model.md`](docs/threat-model.md). R3 HTTP transport exists for the migrated target-web collectors; crawler, fuzzing, security-check, reporting, and extension modules do not.

## Security objective

The platform must make authorized security evidence collection safer to operate, not make it easier to run unbounded or unattended active scanning. The primary security properties are: scoped execution; least privilege; data minimization; authenticated and authorized access; evidence provenance; reliable cancellation; tamper-evident auditability; and explicit uncertainty.

## System assets

| Asset | Sensitivity | Required protection |
| --- | --- | --- |
| Authorization record and scope version | Defines legal and technical boundary for active work. | Immutable approval context, expiry/revocation, deny precedence, audit trail. |
| Project/organization data | Separates customers, teams, and environments. | Tenant/object authorization, query filtering, audit logs, tested isolation. |
| Scan/job request | Can initiate network activity. | Authenticated requester, approved scope snapshot, validation, budget, cancellation, idempotency. |
| Target resolution and redirect chain | Can induce egress to unexpected systems. | Central URL/DNS/redirect validation, private/reserved-address policy, rebinding controls. |
| Raw observations and exported evidence | May contain internal names, headers, paths, source code strings, and timestamps. | Encryption/retention/export policy, redaction/minimization, access control, audit. |
| Potential secrets and credentials | High-risk sensitive material even when unconfirmed. | Redaction, no validation/reuse, restricted access, incident workflow, no logs. |
| External provider credentials | Could expose an account or third-party data. | Secret manager, least privilege, rotation, no browser/client exposure, audit. |
| Plugins and optional executables | Can add code execution and network behavior. | Signed/reviewed distribution policy, declared permissions, scope inheritance, resource limits, isolation. |
| Release pipeline and artifacts | Controls user trust in Wraith binaries. | Pinned CI, dependency review, checksums, later signing/provenance decision, protected release access. |

## Trust boundaries

```text
Operator / API principal
        |
        v
Authentication + object authorization
        |
        v
Project scope + authorization record -----> audit event stream
        |
        v
Job and target policy gateway
        |                         \
        v                          -> denied / expired / over-budget stop
Approved collection providers
        |
        v
Observation and finding store -----> authenticated UI / reports / exports

Optional boundaries: external APIs, optional binaries, workers, cloud credentials, plugins, AI analysis.
Each boundary is disabled until separately configured and reviewed.
```

## Threats and required controls

| Threat | Scenario | Required control before enabling the related subsystem |
| --- | --- | --- |
| Scope bypass | A user, redirect, plugin, worker, or discovered value submits a target outside approval. | **R1:** central deterministic deny-overrides-allow evaluator with immutable SQLite scope versions, project isolation, expiry, revocation, and decision traces. Every future consumer must use it. |
| SSRF and DNS rebinding | A URL resolves or redirects to private, link-local, metadata, or otherwise unapproved addresses. | **R3 for migrated target-web paths:** independent target and resolved-address decisions, controlled resolution/pinned dialing, manual redirect reauthorization, and private/reserved destination filtering. Provider and subprocess paths remain separate exceptions. |
| Proxy scope bypass | An authorized hostname is routed through a proxy to an unauthorized or unsafe target. | R3 authorizes the actual target before proxy connection; proxy configuration is explicit HTTP(S)-only and invalid configuration fails closed. The chosen proxy remains an operator-managed transport trust boundary. |
| Crawler trap or scope expansion | Links, forms, robots, or sitemaps attempt to induce unbounded traversal or third-party egress. | R4 uses canonical deduplication, depth/page/body/query bounds, same-origin filtering, and R3 for every fetch; R1 remains final authorization. |
| Passive-inventory leakage or parser exhaustion | Persisted evidence or a local specification crosses projects, exposes values, or consumes excessive memory. | R5 uses project-filtered R2 reads, stable identities, bounded endpoint/parameter/asset/spec/path/operation limits, generic parser errors, and zero network I/O. |
| Retry or capacity bypass | Retries/concurrent requests create unbounded or unauthorized egress. | R3 retries restart the protected path and default to one attempt; unsafe methods are not replayed by default. A cancellation-aware local limiter and bounded concurrency gate apply to every migrated request attempt. |
| Authorization expiry or replay | A schedule or retry uses stale approval after a project/scope changes. | **R1:** expiring/revocable authorization record is evaluated at decision time. Job-level revalidation, cancellation, and audit events remain deferred until R7. |
| Tenant data leakage | API query, export, cache, WebSocket event, worker, or report crosses project boundaries. | Object-level authorization at every read/write/event path; project-filtered queries; isolation tests. |
| Sensitive evidence exposure | Raw fixture/scan result, potential secret, cloud metadata, or report is read by an unauthorized party. | **R2:** typed immutable observations bound to an explicit project, bounded metadata payloads, and redaction of sensitive HTTP headers. Retention, encryption, export, access logging, and incident procedures remain later design work. |
| Unsafe external tool execution | Plugin or adapter interpolates shell data, uses arbitrary flags/targets, or exceeds scope. | Argument-array execution, validated parameters, capability declaration, timeout/output/resource caps, scope recheck, test fixtures. |
| Provider/API abuse | A provider key is exposed or a source is used beyond its terms/rate/authorization. | Server-side secrets, cache/rate policy, terms review, source provenance, disabled-by-default configuration. |
| Worker compromise | A worker executes an altered or unaudited job, registers false capability, or leaks data. | Mutual worker identity, signed/verified job payloads, least privilege, heartbeat/audit, narrow capability grants. |
| Plugin supply-chain compromise | Third-party code runs inside the platform or widens scan behavior. | Explicit plugin trust model, declared permissions, review/signing policy, version pinning, isolation, safe default disabled state. |
| Risk/finding overstatement | A correlation or AI summary is displayed as proof of a vulnerability or exploitability. | Separate evidence/inference/recommendation models; confidence/evidence/rule version required; analyst state; no automatic confirmation. |
| Abuse of automation | Scheduled or distributed execution is used as an unauthorized scanner. | Project-level approval, scope snapshots, budgets, rate limits, expiry, notification/audit, no unattended default. |
| Audit tampering | A user changes, deletes, or forges scope/job/access records. | Append-oriented audit design, protected writer, retention policy, administrative review. |

## Mandatory security gates

| Planned change | Gate that must pass first |
| --- | --- |
| New active protocol, crawler, or provider | Scope decision, target-gateway tests, budgets, source policy, and subsystem threat-model update. |
| API, authentication, WebSocket, or dashboard backend | Identity model, object authorization, rate limits, audit design, secret policy, integration tests. |
| Scheduler, queue, or worker | Job contract, authorization expiry/revalidation, cancellation, idempotency, resource budget, operational owner. |
| Cloud or AD connector | Credential model, least privilege, tenant/data classification, provider/AD scope policy, fixture-first tests. |
| Vulnerability/risk/attack-path features | Evidence model, confidence semantics, rule versioning, false-positive handling, review workflow, no exploit automation. |
| Plugin system | Plugin permission model, code trust/distribution approach, isolation, scope inheritance, failure containment. |
| AI analysis | Data-sharing decision, output labeling, prompt/input minimization, no autonomous execution or scope override. |

## Explicit non-goals

This platform evolution excludes destructive exploitation, credential guessing/replay, persistence, malware deployment, unauthorized lateral movement, arbitrary target expansion, public-range scanning, and autonomous offensive action. A technical control cannot replace real authorization; Wraith must fail closed when ownership, scope, approval, or data-handling status is ambiguous.

## Current implementation alignment

The existing Phase 1–6 controls already demonstrate several desired patterns: explicit scope validation for local discovery, `--authorized` gates, bounded collection, optional-tool flags, redacted potential-secret persistence, local-first SQLite evidence, fixture-only dashboard rendering, pinned CI actions, and documented non-guarantees. R1 adds a policy evaluator and SQLite-backed immutable project scope records. R2 adds project-isolated canonical web evidence and sensitive-header redaction. R3 adds the shared transport gateway for the migrated target-web collectors, requiring `scan --project` and preserving explicit exceptions for provider APIs and optional binaries. Future work must extend those controls rather than treating the roadmap as permission to remove them.
