# R21 Architecture Audit — Continuous Assessment Analytics & Historical Intelligence

## Verified starting state

R21 begins on `feature/r21-continuous-assessment-analytics` at the committed R20 revision `24cd2d8f59055838421787c0b6eb840ca55bf66b`. The local `main` reference remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`; it must not be merged, rebased, or otherwise modified by R21.

R21 is a **local, deterministic, project-scoped historical analytics layer**. It analyzes already persisted R18 comparisons/snapshots, R19 evaluations/actions, and R20 recommendation state/audit lineage. It is not an assessment runner, scheduler, scanner, transport, evaluator, remediation executor, or finding/risk lifecycle owner.

> An R21 trend or Assessment Health Index describes the bounded recorded history selected by its window. It does not prove remediation, current exploitability, authorization, security, or the absence of unrecorded issues.

## Verified authoritative seams

| Concern | Existing authoritative owner | R21 consumption rule |
| --- | --- | --- |
| Historical snapshot and regression meaning | R18 `internal/regression`, `regression_snapshots`, and `regression_comparisons` | R21 parses and revalidates canonical snapshots, reconstructs each comparison with `regression.Compare`, and aggregates only canonical change types. It never writes or reinterprets R18 state. |
| Policy, baseline, evaluation, and recommendation meaning | R19 `internal/continuousassessment` and `assessment_*` storage | R21 validates persisted evaluation JSON with the R19 validator and reads immutable R19 actions as recommendation origins. It does not evaluate policy or change action status. |
| Governance lifecycle and audit lineage | R20 `internal/governance`, `governance_*` storage | R21 validates R20 state/events and aggregates lifecycle timestamps only when explicit audited data exists. It never transitions, expires, completes, or otherwise writes governance state. |
| Evidence and attack-surface signal | R18 canonical snapshot evidence, endpoint IDs, parameter IDs, and coverage | R21 aggregates only the safe normalized fields already stored in R18 snapshots. It does not read raw evidence payloads, URLs, or rebuild R11.6 identity. |
| Report-safe output | R16 `internal/reportmodel`, `internal/reporting`, and report command | R21 contributes a safe projection to the existing report snapshot and renderer. It does not create a second report engine. |
| SQLite compatibility | R1–R20 `internal/storage` migration contract | R21 adds only `020_r21_analytics.sql`, uses parameterized project-filtered reads, and persists at most immutable bounded derived snapshots. |

## Bounded R21 model

R21 introduces a pure `internal/analytics` package and separates historical source normalization from deterministic aggregation. The storage adapter is responsible for reading, validating, and bounding source records. The pure model receives no database handle or raw payload and returns a canonical `AnalyticsSnapshot` that can be rendered, exported, or stored as an immutable derived artifact.

| R21 record | Purpose | Source-of-truth boundary |
| --- | --- | --- |
| Historical assessment record | Normalized timestamp, safe source fingerprints, regression/evaluation/governance/evidence/coverage counters, and source limitations. | In-memory, derived only from verified R18–R20 records. |
| Analytics snapshot | Windowed metrics, trends, health index, anomalies, data quality, limitations, and deterministic fingerprint. | Pure derived artifact; optional immutable cache only. |
| Cached analytics snapshot | Reusable immutable serialization plus source fingerprints. | Valid only when schema, project, fingerprint, and all source fingerprints still match. It is never an alternative source of truth. |

No R21 type holds raw evidence, request/response bodies, credentials, raw URLs, descriptions, governance reason text, or arbitrary serialized source objects. Identifiers are length-capped, secret-screened, and represented as canonical fingerprints where a source reference is needed.

## Time, limits, and data quality

All R21 timestamps are UTC. The CLI accepts RFC3339 timestamps and positive duration windows only. It rejects negative limits, reversed ranges, windows larger than 366 days, or selection results larger than the fixed configured record/event/action limits. Sort order is `timestamp`, then stable fingerprint/identifier tie-breakers; filesystem order, SQLite row order, locale, and machine-local time do not affect output.

R21 explicitly records `complete`, `partial`, `insufficient`, or `contradictory` data quality. It carries source count, valid count, excluded count, sorted exclusion reasons, and sorted limitations. An absent source or an invalid persisted payload is never silently interpreted as a zero or a healthy state.

## Trend, anomaly, and health contract

R21 compares two comparable chronological halves of the selected historical window. Each trend uses explicit counts from authoritative fields: canonical R18 regression items, R18 stale-evidence markers and coverage, R19 evaluation status, and R20 unresolved governance state. A lower recent regression/backlog/stale-evidence count is `improving`; a higher count is `degrading`; equal counts are `stable`; fewer than two comparable records is `insufficient-data`.

The optional Assessment Health Index is a bounded 0–100 operational-history indicator, not a vulnerability or risk score. It deducts documented fixed weights only for canonical policy failures, regression items, stale evidence markers, and unresolved governance backlog. Missing dimensions cause an explicit limitation and cannot improve the index. A deterministic anomaly is emitted only when the recent half has more than twice the prior-half count for regression items, stale evidence, policy failures, or unresolved governance recommendations. Each anomaly names its metric, observed value, reference value, threshold, and safe reason.

## Explicit non-goals

R21 does not create findings, rescore risk, infer resolution from absence, execute assessments, alter R17 evidence, alter R18 snapshots/comparisons, alter R19 policies/baselines/evaluations/actions, alter R20 states/decisions/events, create schedules, use HTTP/DNS/sockets/subprocesses, call cloud services, store credentials, use telemetry, or automatically execute recommendations. `unknown`, unavailable, malformed, cross-project, stale-cache, forged, and insufficient source state must remain explicit and fail closed where a verified analytical conclusion is required.

## Acceptance criteria

R21 is acceptable only when every source query is project-scoped and bounded; all sourced R18/R19/R20 data is revalidated before use; outputs and fingerprints are deterministic; missing or contradictory history is reported explicitly; persistence is immutable, idempotent, and source-lineage verified; JSON/Markdown/HTML/terminal paths are safe; no forbidden active-operation primitive exists; and unit, integration, fuzz, benchmark, migration, restart, CLI, report, race, and full release-quality checks pass on the dedicated feature branch without modifying `main`.
