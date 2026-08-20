# R20 Architecture Audit — Continuous Assessment Operations and Governance

## Verified starting state

R20 begins on `feature/r20-continuous-assessment-governance` from R19 commit `78187607480f48207ada578330426028a3481aa0`. The local `main` reference remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`; R20 must not merge to or otherwise modify `main`.

R20 is a **local, deterministic, project-scoped governance layer** over persisted R18/R19 state. It records operator decisions about existing R19 recommendations. It is not an assessment runner, task executor, scheduler, transport, scanner, or finding/risk lifecycle owner.

> A governance decision records an operator's treatment of an existing recommendation. It does not prove remediation, revalidation, authorization, exploitability, or current vulnerability state.

## Verified reusable owners

| Concern | Existing authoritative owner | R20 consumption rule |
| --- | --- | --- |
| Authorization, transport, budgets, and execution | R1, R3, R10.5, R13.2, R14, and R15 | R20 stays offline and creates no HTTP client, resolver, dialer, socket, subprocess, scheduler, or task dispatch. Any future executor needs separately reviewed delegation through existing owners. |
| Immutable historical state and regression semantics | R18 `internal/regression` and R18 storage | Load exact project-scoped snapshots and comparisons by stored fingerprints. R20 does not recalculate, reinterpret, mutate, or replace R18 state. |
| Policy, baseline, evaluation, decision, and recommendation semantics | R19 `internal/continuousassessment` and `assessment_*` storage | Load and validate canonical R19 JSON/fingerprints. R20 does not parse a new policy format or duplicate R19 evaluation/recommendation behavior. |
| Finding, risk, surface, campaign, and evidence ownership | R11.5, R11.6, R14, and R17 | Summarize only explicitly stored R19/R18-derived states. Do not create findings, rescore risk, modify campaign state, rebuild graphs, or infer missing evidence lineage. |
| Rendering and safe local output | R16 `internal/reportmodel`, `internal/reporting`, and report command helpers | Add a normalized governance projection only. Reuse terminal, JSON, Markdown, and escaped self-contained HTML rendering; do not create a second renderer. |
| SQLite conventions | `internal/storage` migrations and project-filtered records | Add exactly migration `019_r20_governance.sql`; use parameterized project-filtered reads and one transaction for every state transition plus audit event. |

## Bounded R20 data model

R20 introduces the pure `internal/governance` package. It owns only governance-specific, fingerprinted state: `AssessmentStatus`, `RecommendationState`, `OperationalDecision`, immutable `GovernanceEvent`, and deterministic `GovernanceStatus`. All R18/R19 references remain IDs/fingerprints and are project-scoped, syntactically bounded, secret-screened, and verified against canonical persisted forms.

The R19 `assessment_actions` record remains immutable and always has R19 status `recommended`. R20 therefore adds a separate current governance-state record keyed by `(project_id, action_id, evaluation_id)` rather than updating the R19 action. Absence of an R20 state record deterministically means `recommended`; each successful transition materializes the resulting R20 state and appends one immutable governance event.

| New R20 record | Purpose | Persistence boundary |
| --- | --- | --- |
| Recommendation governance state | Current operational state, source R19 action/evaluation fingerprints, and current state fingerprint. | Mutable only through expected-state transactional transition; never changes R19 action data. |
| Operational decision / governance event | Immutable who/what/why/when record of one transition, including previous/resulting state fingerprints. | Append-only and idempotent by deterministic event fingerprint; a failed event insert rolls back the state write. |
| Derived governance status | Latest policy/baseline/evaluation/comparison summary, unresolved recommendations, staleness, and explicit limitations. | Pure in-memory projection; no historical mutation or invented provenance. |

## Lifecycle, concurrency, and staleness contract

Valid transitions are explicit and fail closed: `recommended -> acknowledged|accepted|deferred|rejected`, `acknowledged -> accepted|deferred|rejected`, `accepted|deferred -> completed|expired`, and `recommended|acknowledged|accepted|deferred -> expired`. Terminal `rejected`, `completed`, and `expired` states cannot return to an earlier state. Every transition requires a project, R19 action identity, evaluation identity, exact expected state, bounded secret-free rationale, bounded actor/context, and injected UTC timestamp.

The storage adapter uses a single SQLite transaction to load the current state, validate the expected-state comparison, write the new state using optimistic matching, and append immutable decision/event records. A unique project/action/evaluation state key and conditional update make concurrent conflicting transitions fail closed; if either state or event persistence fails, the transaction rolls back. Replaying the identical deterministic event is idempotent and cannot generate duplicate audit history.

Staleness is derived, not stored. It is reported when a configured maximum age is exceeded. R20 exposes missing R17 freshness and absent R19 evaluation data as explicit `unknown`/limitation states rather than fabricating a claim; authorization-expiry status remains outside R20 because it performs no active execution.

## CLI, CI, and report projection

R20 adds `wraith govern status|recommendations|acknowledge|accept|defer|reject|complete|history|check`. Every command requires a selected project; all transition commands also require recommendation/action identity, expected state, non-empty bounded reason, and explicit action. The commands remain offline and require no R1 authorization because they do not invoke assessment execution.

`govern check` uses separate governance sentinels and the existing process classifier: exit `0` for healthy, `1` for a governance failure, `2` for invalid input, and `3` for explicitly classified internal governance errors. Strict mode fails for failed R19 policy, detected regression, stale/unknown status, and unresolved high-priority R19 actions; R19 contains no distinct critical-priority action, which remains an explicit limitation.

R16 report integration exposes aggregate governance posture only in executive output. Technical output includes safe fingerprints, recommendation state, decision/event lineage, deterministic stale reasons, and limitations. All existing output escaping and local `0600` output-file behavior remain authoritative.

## Explicit non-goals

R20 rejects a second scanner, crawler, policy parser, evaluator, HTTP stack, DNS resolver, socket, subprocess, scheduler, worker, remote API, cloud service, credential store, report renderer, finding/risk engine, graph rebuild, campaign/task creator, or remediation executor. It does not modify R11.5 findings/risk, R14 campaigns, R17 evidence snapshots, R18 snapshots/comparisons, or R19 policies/baselines/evaluations/actions. It does not treat unknown evidence, coverage, authorization, or historical membership as healthy.

## Acceptance criteria

R20 is acceptable only if its pure lifecycle and status models are deterministic, bounded, secret-screened, and project-isolated; stored R18/R19 references are revalidated; transitions/events are atomic, idempotent, and concurrency-safe; malformed, forged, secret-bearing, cross-project, replayed, and stale inputs fail closed; recommendations remain non-executing; R16 renders the only report outputs; no prohibited egress primitive appears; migration/restart/rollback/fuzz/benchmark/security/report/CLI/race/full-quality gates pass; and the dedicated R20 branch is committed and pushed without merging `main` or starting R21.
