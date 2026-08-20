# R21 Analytics Contract

## Scope and schema

R21 exposes schema version `r21.v1` through `wraith analytics` and the existing R16 reporting path. It is offline, deterministic, project-scoped, and read-only against R18/R19/R20 source records. An optional analytics cache is a derived immutable artifact, not a source of truth.

## Window selection

Every command requires `--project` and `--db`. A window is selected by exactly one of: no range (bounded most-recent history), `--since DURATION` with optional `--until`, `--last N`, or `--from TIMESTAMP --to TIMESTAMP`. All timestamps are UTC RFC3339. Invalid, reversed, oversized, negative, secret-bearing, or traversal-bearing inputs fail with invalid-input semantics.

| Input | Rule |
| --- | --- |
| `--since` | Positive duration no greater than 366 days. The caller supplies the deterministic `--until` reference when reproducible output is required. |
| `--until`, `--from`, `--to` | RFC3339/RFC3339Nano timestamp normalized to UTC. |
| `--last` | Positive bounded count of chronological source records. |
| no selector | The most recent bounded historical records, with an explicit `default_window_applied` limitation. |

## Metric definitions

| Metric | Numerator / value | Denominator and limitation |
| --- | --- | --- |
| Regression count | Canonical R18 comparison items representing new findings, risk increases, stale evidence, contradictions, or coverage decreases. | Count only; unavailable if no verified comparisons. |
| Regression frequency | Verified comparisons containing at least one regression item. | Verified comparison count. |
| Policy failure count | R19 evaluations with canonical `failed` status. | Evaluation count. |
| Governance backlog | Current R20 states in `recommended`, `acknowledged`, `accepted`, or `deferred`. | Current validated state count. |
| Governance lifecycle counts | Valid R20 recommendation states by explicit lifecycle state. | Current-state count; not an inferred historical transition count. |
| Recommendation age | `as_of - R19 action created_at` for a validated recommendation. | N/A if the origin action or timestamp is unavailable. |
| Lifecycle durations | Difference between the explicit R20 event timestamp and the origin timestamp for acknowledge, accept, or complete. | N/A when that transition does not exist. |
| Evidence freshness | R18 snapshot evidence entries with fresh/stale/contradictory/unsupported values where the canonical value exists. | N/A when no verified evidence records are in window. |
| Attack-surface trend | Canonical R18 endpoint and parameter counts, plus coverage numerator/denominator. | N/A when snapshots are absent or coverage definitions are not comparable. |
| Assessment cadence | Verified R19 evaluation timestamps, adjacent UTC intervals, and latest age relative to supplied `as_of`. | N/A with fewer than two evaluations. |

## Trend and health classifications

Trend classifications are `improving`, `stable`, `degrading`, or `insufficient-data`. R21 sorts valid records, splits them into chronological halves, and compares totals. Fewer than two records yields `insufficient-data`. Metrics where lower is better (regressions, policy failures, stale evidence, governance backlog) improve when recent is lower, degrade when recent is higher, and are stable when equal. Coverage improves/degrades only when both halves expose the same positive-denominator coverage definition.

The Assessment Health Index uses a fixed 100-point starting value, bounded to 0–100. It deducts 20 for one or more policy failures, 20 for one or more regression items, 15 for one or more stale/contradictory evidence items, and up to 20 for unresolved governance backlog. It reports every available dimension and limitation. It never replaces R11.5 risk or claims to be a vulnerability score.

## Data quality and source integrity

`complete` means all selected records validate and required source dimensions are available. `partial` means at least one valid record exists but a source is absent or excluded. `insufficient` means too little valid history exists for a requested analytical conclusion. `contradictory` means validated source references disagree or an integrity mismatch was detected. Exclusions list their safe reason; raw malformed source content is never emitted.

R21 revalidates R18 snapshot fingerprints and reconstructs R18 comparisons. It validates R19 evaluations with the canonical R19 validator and validates R20 state/events with the canonical R20 validators. A cross-project reference, invalid fingerprint, source mismatch, malformed JSON, secret-like identifier, cached source mismatch, or cache schema mismatch fails closed.

## Commands and output

R21 provides `summary`, `trend`, `regressions`, `governance`, `health`, `compare`, and `export`. JSON output is canonical, schema-stable, UTF-8, bounded, and sorted. Markdown, HTML, and terminal output escape untrusted fields through the existing R16 rendering boundary. Export paths are local, bounded, non-traversing paths and retain the existing secure output-file permission policy.

All commands only read source records and may optionally save a verified immutable derived snapshot. No command opens a network connection, starts a process, performs DNS resolution, creates a worker, starts an assessment, transitions governance state, or executes a recommendation.
