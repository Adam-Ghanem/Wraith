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
| Client-side source execution or static-analysis exhaustion | A JavaScript asset or source map attempts to induce execution, remote fetching, cross-project reads, parser crashes, or unbounded output. | R6 accepts only explicit local bytes, validates with bounded parsing/traversal/source-map limits, uses project-filtered R2 reads, stores value-minimized metadata, and contains no runtime, browser, subprocess, DNS, socket, or HTTP analysis path. |
| Generic mutation abuse or evidence leakage | A fuzz target, mutation, redirect, body, response, or header causes unbounded egress, scope bypass, credential exposure, or overstated conclusions. | R7 requires explicit project endpoint/parameter selection, fixed profiles and budgets, safe-method default, sensitive-header rejection, cancellation-aware local jobs, R3-only execution, R1/R3 redirect and destination controls, and redacted metadata-only fuzz observations. It creates no findings. |
| Wordlist, soft-404, or virtual-host scope abuse | A local wordlist entry, recursive child, Host override, response body, redirect, or project-local base selection attempts to expand scope, cause request explosion, or leak content. | R7.5 accepts explicit local bounded files only; validates paths/labels; requires selected-project base evidence; bounds rate, workers, duration, body size, request count, and recursion depth; uses R3 for every baseline/candidate; separately sends each Host override through R1 before DNS; detects soft-404s by bounded fingerprints; and persists only redacted structural observations. It is not an R4 crawler and creates no findings. |
| Validation overreach or evidence leakage | A validator, selected endpoint, response body, lifecycle label, or persisted result attempts to create extra egress, disclose response contents, imply exploitability, or cross project boundaries. | R8 accepts an explicit selected-project endpoint, caps execution at one R3 request and one MiB of evidence, evaluates R1/R3 before any network I/O, performs deterministic passive checks only, derives reproducibility keys, persists redacted validator/rule/lifecycle metadata, and emits only `observed` results automatically. It has no payload, credential, brute-force, form-submission, alternate transport, or exploitation path. |
| Intelligence overreach or cross-project correlation | Graph inputs, candidate identities, evidence IDs, confidence calculations, or change windows cause tenant mixing, remote egress, fabricated root causes, or remediation claims. | R9 validates project identity at every graph/correlation/change boundary, uses stable canonical IDs and same-origin typed edges, deduplicates deterministically, exposes reasons for bounded confidence, records removed evidence as a state rather than remediation, and has no client, resolver, socket, advisory feed, graph service, or exploitability inference. |
| Authentication testing abuse or secret leakage | Credential input, identity metadata, response bodies, or retries widen scope, leak secrets, or trigger account controls. | R10 requires `--authorized` and `--attack-auth` before input loading; uses bounded local sources, R1/R3-only live requests, project-scoped identities, secret-free persistence, and immediate lockout/MFA/CAPTCHA/rate-limit stops. |
| Orchestrator scope expansion, replay, or misleading output | A profile, resume request, phase adapter, shared budget, stored event, or report attempts to add egress, replay an unsafe authentication action, cross projects, exhaust capacity, persist a secret, or imply unrecorded coverage. | R10.5 builds an explicit authorized plan, reuses existing R1/R3 paths rather than a new client, applies one global request/rate/concurrency budget, persists project-filtered secret-free run/phase/event metadata, validates resume configuration fail-closed, resumes only incomplete non-attack phases, and labels local reports as recorded outcomes and limitations rather than inferred findings. |
| Mutation-plan secret leakage or execution bypass | A request template, candidate strategy, fingerprint, cross-project R2 identity, or later caller leaks credentials, creates unbounded variants, or turns local planning into unauthorized egress. | R11.1 requires authorization intent and matching project-local R2 endpoint/parameter identities, bounds variant/value/body/JSON depth, rejects sensitive header names, keeps templates memory-only, and emits hashes rather than raw request content. It has no network or execution capability; future execution must separately enforce R1/R3. |
| Discovery candidate overreach, secret leakage, or active-probe bypass | A malformed or cross-project seed, sensitive local wordlist entry, unbounded heuristic, passive command, or verifier bypasses project scope, performs unexpected egress, or stores a credential/body as discovery evidence. | R11.2 canonicalizes through R2, requires matching R5 inventory project IDs, bounds all candidate/wordlist inputs, rejects sensitive paths/values, stable-deduplicates provenance, and defaults to no network. Explicit verification permits only `HEAD` via injected R3, consumes R10.5 budget/rate/concurrency controls, disables redirect following, and emits redacted metadata-only R2 observations. |
| Injection-test escalation, evidence leakage, or false confirmation | An arbitrary/destructive payload, unsafe method, direct client, cross-project identity, response body, or differential signal expands scope, leaks data, destabilizes a service, or becomes an unsupported claim. | R11.3 allows only immutable short canaries, project-matched R2 identities, explicit authorization, `GET`/`HEAD`, injected R3, R10.5 controls, duration/cancellation limits, and a `429` stop. Values are memory-only; observations are redacted. Signals use an R8 submit seam, never create findings, and do not invoke R9. |
| Validation overreach, unstable response false positive, or lifecycle bypass | A stale/cross-project signal, repeated arbitrary request, policy lapse, generic 5xx, raw body, or candidate is treated as a confirmed vulnerability or bypasses R8/R9. | R11.4 accepts one project-matched R11.3 test/signal pair; rechecks R1 before each injected R3 request; bounds profiles to one/two/three pairs; uses R10.5 capacity controls; stops on `429`; classifies generic 5xx and request failures as inconclusive; keeps payloads memory-only; writes only R8/R2 redacted evidence; and submits only validated candidates to R9. |
| Risk-intelligence inflation, cross-project suppression, secret leakage, or finding-state bypass | A rejected input becomes an active finding, a score is opaque/non-deterministic, a project suppresses another project’s fingerprint, or payload/credential data enters local findings output. | R11.5 accepts only validated/repeatable/evidence-backed R11.4 candidates with R9 correlation, scores fixed bounded factors under `r11.5-v1`, defaults missing context to unknown, enforces project/fingerprint suppression matching and expiry, uses append-only history, and omits candidate fingerprints/raw secrets from local output. It has no egress or execution path. |
| Graph inference, cross-project campaign planning, or autonomous execution | An unsupported relationship is presented as an attack path, data from another project is included, a graph change triggers testing, or a local plan bypasses R10.5/R1/R3. | R11.6 requires known project-local nodes/edges, stable deterministic identity, bounded snapshots and task budgets, local-only surface/campaign dry-run commands, and explicit limitations. It has no direct transport, scheduler, worker, scanner, or validation behavior. |
| Integration regression or CI safety drift | A future change bypasses authorization, leaks another project’s local data, changes dry-run behavior, or removes a required quality gate without detection. | R12 adds temporary SQLite CLI smoke coverage for explicit authorization/project isolation/local dry-run paths and a CI step for smoke/migration checks. It creates no new runtime egress or security authority. |
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
