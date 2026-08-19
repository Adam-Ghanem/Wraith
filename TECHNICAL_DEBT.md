# Wraith Technical Debt and Platform-Gap Register

**Status:** Evidence-based audit register. Items are prioritized planning work, not claims of present vulnerabilities.

## Audit baseline

The audited repository contains 17 Go packages, 31 non-test Go source files, 36 Go test files, one frontend test file, three embedded SQLite migrations, one GitHub Actions workflow, and a static React dashboard. The current code is focused and relatively compact. Most entries below are **deliberate platform gaps** created by the Phase 1–6 scope, not defects to be “fixed” by adding broad capabilities without design review.

## Priority definitions

| Priority | Meaning |
| --- | --- |
| P0 | Required design/control work before adding a hosted, scheduled, multi-user, or broader active-scanning capability. |
| P1 | Required before the related platform subsystem can be described as production-ready. |
| P2 | Important maintainability, scale, or developer-experience improvement after the required security boundaries exist. |
| Deferred | Intentionally not in scope until a user need, authorization model, and threat-model review justify it. |

## P0: platform-boundary prerequisites

| Item | Evidence | Risk if skipped | Required remedy |
| --- | --- | --- | --- |
| Central project-scope engine | Current local scope validation is IPv4/CIDR-specific; `scan` relies on a CLI authorization assertion and domain options. | A future API, scheduler, worker, redirect handler, or plugin could apply inconsistent target policy. | Define a shared deny-overrides-allow evaluator for domain, subdomain, IPv4/IPv6 CIDR, URL, and port. Require all network paths to request a versioned scope decision. |
| Central outbound target gateway | HTTP collection is orchestrated from CLI and uses multiple collection packages. | New fetch/crawler/provider paths can bypass redirect, DNS, private-address, or budget controls. | Introduce one target-validation and request-budget boundary before adding new protocols, crawling, API discovery, or remote inputs. |
| Authorization record and lifecycle | `--authorized` is explicitly documented as self-attestation only. | Scheduled, multi-user, or remote execution would have no durable authorization evidence or expiry/revocation semantics. | Model project-scoped authorization records, requester identity, scope version, activity class, expiry, and approval state; fail closed on absence. |
| Tenant and object authorization design | Current storage is intentionally local single-user SQLite, and the dashboard is static. | Adding API/auth/UI endpoints without object-level authorization risks cross-project disclosure. | Design organization/project ownership, RBAC, object authorization, audit events, and data-retention/deletion rules before any hosted service. |
| Data classification and secret handling | Existing JS secret-like values are redacted before persistence; other evidence remains local filesystem data. | Hosted persistence or notifications could expose sensitive scan output. | Define collection minimization, encryption, retention, export, redaction, notification, and incident-handling policies before remote storage or delivery. |
| Scheduler/worker execution contract | No current scheduler, queue, worker, or job model exists by design. | A background run could outlive authorization, lose cancellation, repeat unsafe work, or drift from scope. | Define immutable jobs with scoped inputs, budgets, approval state, cancellation, retries, idempotency, progress, and audit logs before automation. |

## P1: data, reliability, and security hardening

| Item | Evidence | Consequence | Recommended slice |
| --- | --- | --- | --- |
| Unified asset/observation model | R2/R5/R6 now cover canonical URL/JavaScript assets, endpoints, parameters, and typed append-only client-side observations, while devices, services, certificates, and broader assets remain scan-oriented. | Cross-source deduplication and history remain incomplete outside the implemented web/client-side slice. | Preserve the current R2 identities; add broader entities only through separately reviewed migrations and import adapters. |
| General finding lifecycle | R7 adds typed redacted fuzz observations, but no normalized finding status or analyst workflow. | “Finding,” “confirmed,” and “resolved” could become ambiguous or fabricated. | Create rule/source/version/confidence/evidence-backed findings with explicit states and no automatic confirmation from a version/banner alone. |
| Robust SSRF/rebinding policy | Existing policy recognizes redirect and output-derived scope risk; no centrally reusable gateway exists. | Future crawler, API, webhook, cloud, or plugin code can create new egress paths. | Build deterministic URL/DNS/redirect tests and a single egress policy package before broadening HTTP behavior. |
| R11.1 execution seam | R11.1 creates bounded local request variants only; it deliberately has no R1 evaluator call, R3 dispatcher, active evidence writer, or R10.5 scheduler integration. | Treating candidates as executable work would bypass the system’s active-operation controls. | Keep the planner no-network; design a separately approved executor that consumes R10.5’s shared budgets, checks R1 immediately before dispatch, uses R3 exclusively, emits redacted R2 evidence, and can stop on cancellation or health controls. |
| R11.2 orchestration and candidate persistence | R11.2 provides a bounded CLI/library discovery slice and redacted response observations, but no durable candidate table, R10.5 phase registration, health monitor, or resume semantics. | Treating discovery candidates as durable verified endpoints or independent scheduled jobs would overstate evidence and bypass lifecycle controls. | Add a separately approved project-scoped candidate persistence/phase adapter only with R10.5 lifecycle, R1 re-check, stop/health policies, safe resume, and no duplicate R2 identity model. |
| R11.3 validation and orchestration adapter | R11.3 has a bounded R3/R10.5 runner and validation submit seam, but no R10.5 phase adapter, automatic R8 implementation, R9 invocation, persistent test store, report, or resume semantics. | Treating a differential signal as a confirmed finding or independently scheduling the runner would bypass validation, correlation, and lifecycle safeguards. | Add an approved adapter only after defining R1 re-evaluation, durable records, health propagation, safe resume, R8 evidence mapping, R9 correlation input, and analyst lifecycle states. |
| API authentication and secrets design | No HTTP API, principals, password storage, session scheme, or secret store is implemented. | Copying a generic auth scaffold could introduce severe access-control flaws. | Select identity model, session/API-key format, secret rotation, rate limits, and audit design through a separate threat model. |
| Production database migration path | Current SQLite uses embedded migrations and eight connection settings appropriate to local use. | PostgreSQL/queue/worker assumptions should not leak into the local CLI or be added without migration/backup planning. | Keep SQLite local mode; establish repository interfaces, migration strategy, backup/restore, and load tests before a PostgreSQL adapter. |
| CI coverage for all branches and security tools | CI is strong for Go/web quality but pushes are configured only for `main` and one historical Phase 6 branch. | Feature-branch pushes do not automatically run the workflow; no integration/security-tool release job exists. | Protect `main` with required PR checks; add tested, pinned security checks only after their output and maintenance burden are defined. |
| Release trust | Current release artifacts are checksummed but explicitly unsigned. | Checksums alone do not authenticate a publisher. | Decide whether signing/provenance is needed, document key custody, and test verification before claiming it. |

## P2: maintainability and scale improvements

| Item | Evidence | Recommendation |
| --- | --- | --- |
| Storage API duplication | `SaveScan` and `SaveScanWithAllFindings` overlap in scan/device/subdomain transaction logic. | Consolidate through one internal transactional primitive when a new asset migration requires touching storage; preserve tests and public behavior. |
| Empty internal directories | `internal/authorization`, `internal/cli2`, `internal/probe2`, and `internal/testutil` contain no Go source. | Remove them only after confirming they are not reserved for an approved next slice, or populate them as part of that slice; do not leave speculative package structure. |
| History semantics | Subdomain/device diffs support NEW/REMOVED/CHANGED; finding diffs are currently new-presence oriented. | Define per-entity change semantics and stable identities before presenting comprehensive historical status or risk-change claims. |
| Scale and query planning | Current SQLite queries are appropriate to local scan history, not the stated 10,000+ asset / 100,000+ finding target. | Establish data volume targets, indexes, pagination, archival, and load tests before promising continuous ASM scale. |
| Observability | `slog` diagnostics exist in CLI paths; no service metrics, health/readiness, tracing, or job telemetry exists. | Add structured event/audit schema first, then instrument only deployed service boundaries. |
| Dashboard state | The current frontend is intentionally fixture-only. | Preserve it as an offline evidence viewer; introduce a live UI only after stable API, auth, pagination, and authorization contracts exist. |

## Current strengths that are not debt

The following should not be removed merely to imitate a larger platform: explicit local CIDR validation; opt-in external binaries; non-fatal optional source failures; SQLite migration transactions; fixture-only dashboard rendering; safe React text rendering; potential-secret redaction requirement; reproducible build metadata; dependency/license review; and SHA-pinned CI actions.

## Deferred capabilities requiring separate approval

The supplied roadmap lists distributed workers, remote APIs, multi-tenancy, scheduling, cloud inventory, AD inventory, attack graphs, risk scores, plugins, notifications, reporting, and AI-assisted analysis. They remain **deferred** until the P0 prerequisites, a written scope amendment, a subsystem threat model, test plan, data-retention model, and operational ownership are approved.

## No unsubstantiated defect claims

This audit does not label the current absence of API/auth/scheduler infrastructure as a vulnerability. The project documents those features as out of scope for the implemented Phase 1–6 design. The debt register identifies the controls that must exist **before** those capabilities are added.
