# R22 Architecture Audit — Continuous Assessment Intelligence & Decision Engine

## Verified starting state

R22 begins on `feature/r22-decision-intelligence` at the committed R21 revision `4c0bbae37fe0b99afe28e6c99a235166cec2f602`. The local `main` reference remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`; R22 must not merge, rebase, push, or otherwise alter it. An unrelated, pre-existing logo-exploration ledger change remains in `todo.md` and must be preserved outside the R22 commit.

R22 is a **local, deterministic, project-scoped decision projection layer**. It turns already verified R18–R21 intelligence into explicit, auditable decision candidates and recommendations. It does not execute, schedule, dispatch, scan, request, remediate, authorize scope expansion, or mutate any upstream owner state.

> An R22 recommendation is decision metadata, not remediation, task execution, revalidation, authorization, a finding, a risk mutation, or evidence of security.

## Verified authoritative seams

| Concern | Existing authoritative owner | R22 consumption rule |
| --- | --- | --- |
| Regression and comparison semantics | R18 `internal/regression` and project-scoped regression storage | R22 consumes only a comparison reconstructed with `regression.Compare` from canonical baseline/current snapshots. It never creates a competing regression model. |
| Policy and evaluation semantics | R19 `internal/continuousassessment` | R22 validates persisted `ControlEvaluation` values with R19 validation and treats policy failure state as an input only. It never evaluates, edits, or applies policy. |
| Recommendation lifecycle and audit lineage | R20 `internal/governance` | R22 validates governance state, operational decisions, and events before deriving constraints. It never transitions, accepts, rejects, completes, or expires a recommendation. |
| Historical analytics | R21 `internal/analytics` and `storage.BuildAnalyticsSnapshot` | R22 consumes a freshly reconstructed, canonical R21 snapshot. R21 remains authoritative for trends, health, anomalies, regressions, governance aggregation, and data quality. |
| Report-safe output | R16 `internal/reportmodel`, `internal/reporting`, and report CLI | R22 contributes one read-only decision-intelligence projection to the existing report snapshot and renderer. It creates no new report engine. |
| SQLite schema and derived persistence | `internal/storage` migrations and immutable-cache conventions | R22 adds exactly one project-scoped migration after version 020. Stored decisions are immutable derived snapshots and are served only after fresh source reconstruction. |

## Bounded R22 architecture

R22 separates validation and I/O from pure decision evaluation. The storage adapter loads only project-local, fixed-size R18–R21 source material; canonicalizes and revalidates it; then passes a normalized source bundle to `internal/decisionintelligence`. The pure package contains no database handle, network primitive, filesystem access, or execution path.

| R22 artifact | Contents | Owner boundary |
| --- | --- | --- |
| Validated decision input | A canonical R21 snapshot plus safe source lineage and constraint-relevant status. | In-memory only; produced after project-scoped canonical source reconstruction. |
| Decision candidate | Stable priority, factors, constraints, confidence, quality, allowed/degraded/blocked state, and recommendation metadata. | Pure derived output; not a task or lifecycle owner. |
| Decision snapshot | Sorted candidates, safe source fingerprints, generation window/as-of metadata, limitations, and SHA-256 fingerprint. | Immutable derived artifact. |
| Stored decision snapshot | Bounded serialized projection with immutable fingerprint and source lineage. | Cache only; never a source of truth and never served stale. |

Raw payloads, evidence bodies, credentials, cookies, authorization headers, unrestricted URLs, raw governance reasons, and arbitrary user text do not enter R22 types, persistence, or output. Safe identifiers and explanations are length-capped, template-selected, secret-screened, sorted, and fingerprinted.

## Decision semantics

R22 emits only explicitly supported factors: active or recurring R18 regressions, R21 degrading trend/health/anomaly/data-quality signals, R19 policy failures, R20 unresolved/stale/invalid governance state, and R18 evidence freshness or contradiction state. Each factor has a stable type, bounded positive weight, source fingerprint, deterministic explanation template, confidence, and quality status.

The versioned priority model is deterministic: `P0` immediate, `P1` high, `P2` medium, `P3` low, and `P4` informational. Priority is calculated solely from documented factor weights, then reduced or blocked by explicit constraints. Constraints include `no_valid_evidence`, `source_stale`, `source_contradictory`, `policy_blocked`, `governance_blocked`, `insufficient_coverage`, `invalid_source`, `cross_project_reference`, `fingerprint_mismatch`, and `data_quality_failure`. A blocked candidate remains blocked; R22 never silently upgrades it to allowed.

## Source integrity and determinism

Every source record is project-scoped and revalidated. R22 does not trust stored foreign fingerprints, stored comparison JSON, stored analytics JSON, or project references alone. The adapter reconstructs canonical source forms, recomputes fingerprints, and rejects mismatches, secret-bearing identifiers, impossible timestamps, invalid lineage, malformed state, cross-project references, or stale cached data.

Canonical collections use stable sort keys. Canonical JSON includes all semantic fields but excludes random identifiers, memory addresses, non-semantic runtime timestamps, raw payloads, and secrets. Equal validated source state and explicit `as_of` input produce byte-equivalent output and the same SHA-256 fingerprint. All history, candidates, factors, constraints, lineage references, recommendations, stored JSON, and output sizes are capped.

## Explicit non-goals

R22 does not create a scanner, transport, HTTP/DNS/socket client, subprocess, scheduler, worker, cloud dependency, credential manager, task dispatcher, campaign starter, adapter call, automatic exploit, automatic remediation, automatic finding/risk mutation, scope-expansion mechanism, or policy/governance lifecycle writer. It does not replace R1, R3, R10.5, R13, R14, or R15.

## Acceptance criteria

R22 is acceptable only when pure evaluation is I/O-free; source validation is canonical, project-local, bounded, and fail-closed; persistence is immutable and idempotent; stored snapshots are rejected when source state changes; recommendations cannot imply execution; output is deterministic and escaped; CLI inputs and local paths are constrained; no forbidden active-operation primitive appears in R22 core/CLI/storage; unit, integration, fuzz, benchmark, migration, restart, CLI, report, race, and full release-quality checks pass; and only R22 changes are committed and pushed on the dedicated branch.
