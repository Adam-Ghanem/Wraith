# R14 — Campaign Orchestration and Continuous Assessment Audit

**Baseline.** R14 starts on `feature/r14-campaign-orchestration` from R13.2 commit `ed2b038`; `origin/main` remains `42cb8b2`. The R14 scope is a local, bounded campaign lifecycle around already-existing planning and execution contracts. “Continuous” means an operator can explicitly create a later bounded cycle from newer authorized local evidence. It does not mean a daemon, poller, scheduler, worker, automatic replay, or autonomous target expansion.

## Verified reusable ownership

| Concern | Current owner and verified seam | R14 rule |
| --- | --- | --- |
| Authorization and scope | R1 policy records/evaluator and active scope versions | Store only project/scope-version identifiers; revalidate before every new cycle and execution handoff. Never create a campaign-local authorization decision. |
| Transport and target safety | R3 controlled transport and component owners | R14 owns no HTTP client, DNS resolver, socket, redirect, TLS, proxy, subprocess, or browser path. |
| Assessment planning | R13 `assessment.AssessmentPlan`, task graph, scope snapshot, and profiles | A campaign cycle references one validated deterministic plan; it must not rebuild scanner, mutation, fuzzing, injection, validation, finding, or reporting behavior. |
| Adapter ownership | R13.1 `AdapterRegistry` and single-owner task binding | R14 supplies no alternative registry and does not select an owner dynamically. Missing owners remain fail-closed. |
| Assessment execution | R13.2 `assessmentexec.Engine` | Each explicit cycle delegates to one engine request with the existing shared controls; campaign code never dispatches an adapter directly. |
| Global limits | R10.5 `BudgetManager`, `ConcurrencyController`, `GlobalRateLimiter`, and `RunContext` | A cycle creates one shared R10.5 run context. Campaign counters are audit/accounting data, not a second egress-budget authority. |
| Execution lifecycle persistence | R10.5 `pentest_runs`, `pentest_phase_runs`, and append-only `pentest_events` | Persist actual assessment execution through the R13.2 persistence adapter. R14 must not reinterpret task completion without the execution summary. |
| Evidence, validation, correlation, findings, and risk | R2; R11.4; R9; R11.5 | R14 records only stable reference IDs/fingerprints and summary counts. It never turns a campaign task or adapter signal into a finding. |
| Surface intelligence | R11.6 graph and `Snapshot` / SQLite attack-surface snapshot records | Reference immutable snapshot ID, graph fingerprint, project ID, and source version. Do not duplicate graph nodes or edges into campaign state. |
| Existing campaign concept | R11.6 `attacksurface.CampaignPlan` and `wraith campaign plan --dry-run` | Preserve it as a non-executing analyst recommendation plan. R14 uses a dedicated `internal/campaign` package and a distinct CLI subcommand to avoid type/lifecycle conflation. |
| CLI and CI | Existing local SQLite CLI conventions and R12 smoke tests; CI runs Go tests, race tests, vet, build, web checks, and migration smoke coverage | Add deterministic temporary-SQLite campaign coverage. No external service, real target, or background execution is needed. |

## Existing lifecycle and concurrency facts

R10.5 runs have explicit `created → planning → running → completed|partial|failed|cancelled` transitions and persist project-scoped run/phase/event records. Its budget manager is mutex-protected, its concurrency controller is channel-backed, and its global rate limiter is mutex-protected and cancellation-aware. These are race-sensitive shared controls and must be passed by pointer once per R14 cycle, not copied or replaced.

R13.2 validates a complete plan before work starts; requires a registry and R10.5 controls; rechecks its injected R1 authorization before execution, during scheduling, and directly before registry dispatch; gives each adapter a bounded context; and normalizes only secret-free owner/result references. Its dry-run validates and marks tasks skipped without adapter dispatch or execution-lifecycle persistence. An R14 cycle must preserve these semantics, not emulate them.

Current resume behavior exists only for R10.5’s supported incomplete safe phases. R13.2 deliberately has no automatic replay. R14 must therefore create a later cycle only through an explicit operator command, attach a fresh execution reference, and carry forward completed task identifiers as immutable history so no completed work is silently rerun. Cancellation propagates through R13.2 contexts and then becomes an execution summary; R14 may checkpoint the outcome but cannot restart it automatically.

## R11.6 surface-reference boundary

R11.6 already has deterministic `Snapshot` values containing an ID, project ID, graph fingerprint, source version, timestamp, and node/edge counts. SQLite persists project-scoped snapshots separately from graph node and edge rows. R14 should validate the selected snapshot against the campaign project and retain only this stable reference tuple. A later cycle can compare the prior stored fingerprint/reference with an operator-selected current snapshot using R11.6 diff semantics, but a graph or finding change must still re-enter R1 authorization and R13 planning before execution.

## Threat and failure review

| Risk | Required R14 control |
| --- | --- |
| Cross-project campaign or snapshot reference | Validate project identity for campaign, active scope, plan, R11.6 snapshot, execution summary, and every storage query. |
| Stale, revoked, or expired authorization | Campaign creation and each explicit cycle require an active R1 scope/version; R13.2 performs the final pre-dispatch rechecks. |
| Completed work replay | Persist immutable per-cycle assessment task IDs and execution reference; reject a new cycle that claims prior completion as runnable work. No automatic retry/resume. |
| Parallel budget bypass | Construct exactly one R10.5 `RunContext` per R13.2 handoff. Campaign fields never grant or consume network authority independently. |
| Secret leakage | Reject/omit raw target query values, credentials, cookies, headers, payloads, bodies, and adapter errors. Persist IDs, bounded status/reason codes, timestamps, counts, and fingerprints only. |
| Finding or risk inflation | Treat R13.2 results as execution summaries. Preserve R11.4 → R9 → R11.5 ownership and label campaign state as orchestration, not a security verdict. |
| Implicit continuous execution | Campaign creation, comparison, checkpointing, and later-cycle planning are local operations. A non-dry cycle requires an explicit CLI invocation and authorization flags. |
| Persistence failure or event tampering | Use parameterized existing SQLite APIs and append-oriented events. A failed campaign state transition/checkpoint write prevents the corresponding command from claiming success. |

## Exact R14 boundary

R14 will add a dedicated campaign domain with explicit campaign/task/cycle/checkpoint/event state transitions, deterministic fingerprints, project-scoped SQLite records, and explicit local CLI lifecycle commands. It will capture existing R11.6 snapshot references, validated R13 plans, and R13.2 execution references. It will use injected adapters for R1 scope lookup/evaluation, snapshot lookup, R13.2 execution, and R10.5 lifecycle persistence so package dependencies remain directional and testable.

R14 will not add an HTTP engine, scanner, payload class, fuzzing engine, injection engine, authorization model, credential mechanism, secret store, evidence store, finding engine, report renderer, daemon, scheduler, queue, worker, automatic retry, automatic target expansion, main merge, or R15 work.

## Audit conclusion

There is no architectural contradiction. The existing R11.6 campaign plan is intentionally non-executing, while R13.2 is intentionally generic and injected. A dedicated R14 campaign package can safely join those references without merging their types, provided it delegates every live assessment handoff to R13.2 and persists only campaign orchestration state plus stable references.
