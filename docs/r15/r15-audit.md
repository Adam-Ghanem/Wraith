# R15 Audit — Built-in Active Campaign Adapters

## Baseline and conclusion

R15 starts from `feature/r14-campaign-orchestration` commit `6112a73`; `origin/main` remains `42cb8b2`. The repository already has the three layers R15 must join: R14 has project-scoped campaign/cycle/checkpoint state, R13.2 has a deterministic authorization-aware executor, and R13.1 has a single-owner `AdapterRegistry`. R15 binds only the complete owner contracts: R4 crawl, passive R5 endpoint inventory, and R11.2 Smart Discovery verification. All remaining R13 task types deliberately retain fail-closed typed `ADAPTER_UNAVAILABLE` owners.

> R15 is an integration slice. It must delegate to established R3 and R11 owner seams; it must not reconstruct scanning, payload generation, R1 evaluation, R10.5 limits, evidence, findings, risk, or surface logic.

## Verified lifecycle and ownership

| Concern | Verified current owner | R15 integration rule |
| --- | --- | --- |
| Campaign and checkpoints | R14 `internal/campaign`, project-scoped campaign/cycle/task/checkpoint/event SQLite records | Preserve immutable plan/surface/scope references, checkpoint fingerprints, replay prevention, and dry-run zero-write behavior. |
| Plan and task graph | R13 `assessment.AssessmentPlan`, profiles, deterministic task IDs/dependencies | Use existing task types (`crawl`, `endpoint_inventory`, `js_intelligence`, `baseline`, `smart_discovery`, `mutation`, `fuzz`, `injection`, `validation`, `correlation`, `finding`, `risk`, `attack_surface`, `report`) unchanged. |
| Adapter ownership | R13.1 `AdapterRegistry` | One `TypedAdapter` per known task type. Duplicate, blank, unknown, absent, identity-mismatched, or secret-bearing results fail closed. |
| Execution state | R13.2 `assessmentexec.Engine` | Preserve full-plan validation, fresh R1 authorization before execution/scheduling/dispatch, R10.5 `RunContext`, task deadline, cancellation, deterministic ordering, and secret-free event/result normalization. |
| Authorization | R1 policy scope/evaluator plus CLI `assessmentAuthorizer` | Never inherit authorization from a campaign or prior task. Each real request remains subject to the R3 gateway; R13.2 repeats the plan-level gate. |
| Transport and R2 observation | R3 `httpengine.Engine` with policy gateway and optional SQLite observation sink | Build only the existing configured engine pattern used by `crawl`, `fuzz`, `smart-discover`, and related CLI commands. No direct client, dial, resolver, TLS, or redirect path. |
| Shared limits | R10.5 `BudgetManager`, `GlobalRateLimiter`, `ConcurrencyController` | R15 adapters receive the exact R13.2 task `RunContext`; they do not create an alternative budget, pool, or limiter. |
| Crawl | R4 `crawler.Crawler` over injected R3 client and R2 repository | A possible adapter must map only bounded R13 limits to existing crawler configuration and retain its same-origin/R3 behavior. |
| Discovery | R11.2 `smartdiscovery.Verify` | Existing active seam accepts planned candidates, injected R3, shared R10.5 controls, and R2 sink; it sends bounded `HEAD` requests only. R15 must obtain candidates from existing project-local planning, never manufacture a wordlist scan. |
| Mutation | R11.1 `requestmutation` | It is a bounded, local planner/composer only. R15 can expose planning references, but it cannot claim an active mutation adapter exists without an owner-owned active runner. |
| Injection | R11.3 `injection.Run` | Existing active seam accepts a prebuilt plan and injected R3/R10.5/evidence/validation dependencies. It is restricted to authorized GET/HEAD baseline-plus-bounded-canary work and stops on `429`. |
| Validation | R11.4 `findingvalidation.Run` | Existing active seam performs R1 recheck before every R3 dispatch and hands only validated evidence to R8 and validated candidates to R9. It does not create final findings. |
| Findings and risk | R9/R11.5 | Local, downstream ownership only. R15 may expose stable references returned by owner seams but must not manufacture findings or scores. |
| Attack surface | R11.6 | R14 stores immutable snapshot references. R15 does not rebuild graph semantics or authorize new graph members. |

## Existing configuration facts

`internal/cli/assessment.go` is the owner-registry assembly point used by both direct assessment and R14 campaign execution. It constructs R10.5 controls, R13.2 engine dependencies, and an R1 authorization callback. It now binds `r4.crawler`, `r5.endpoint_inventory`, and `r11.2.smart_discovery`, while retaining explicit unavailable owners for all incomplete contracts. The CLI uses the existing R3 construction pattern: an `httpengine.Engine` configured with `policy.NewGateway(policy.NewEvaluator(database))`, bounded configuration, and the SQLite R2 observation sink.

The R11.2, R11.3, and R11.4 runners are adapter-ready only when their project-local inputs exist: discovery candidates; injection plan/template/parameter; and validation candidate/plan/template/parameter plus R8/R9 submitters. R15 must query or build those inputs only through their existing public planning/storage seams. If any required record, identity match, downstream submitter, or memory-only context is unavailable, the corresponding adapter must return a typed unavailable/blocked outcome and never pretend to have completed work.

## Security invariants

| Invariant | Required R15 treatment |
| --- | --- |
| No new egress | No `http.Client`, `http.NewRequest`, `net.Dial`, resolver, socket, subprocess, or browser primitive in R15. Network work is delegated to injected R3 owner seams. |
| Secret-free context and persistence | Adapter context/result/checkpoint references contain only bounded IDs, task/profile/scope/snapshot references, counts, timings, and allowlisted evidence/finding IDs. Credentials, cookies, authorization headers, payload values, raw request/response bodies, and raw adapter errors are excluded. |
| Scope and project isolation | Every selected record and returned reference must match the campaign project, task target, scope version, and immutable surface snapshot. |
| Dry run | Validate registry/owner/configuration only. It dispatches no adapter, writes no R10.5 cycle/event/checkpoint state, sends no R3 request, and creates no evidence/finding. |
| Failure semantics | Missing adapter input, owner mismatch, `429`, policy denial, budget/concurrency/rate failure, cancellation, timeout, dependency failure, invalid checkpoint, or invalid result stops/blocks the affected execution truthfully. |
| Replay | R14 remains responsible for durable completed-task state. R15 must not bypass R13.2/R14 cycle filtering or mark a task complete without a validated owner result. |

## Rejected integrations

R15 must reject the following implementation shortcuts: a generic HTTP assessment adapter that calls a new client; a new crawler or wordlist loop; a new mutation or injection payload generator; a campaign-local R1 evaluator; a campaign-local limiter; raw evidence/finding persistence; automatic graph-driven scope expansion; fake successful results; automatic retry/resume/scheduling; and direct invocation of R11.4 findings/risk creation.

## Proposed bounded adapter set

The implementation audit will first prove each candidate adapter with a failing test and localhost-only fixture. It may register built-in owners only where the exact inputs can be resolved from the campaign’s selected project and where the existing R3/R10.5/R2/R8/R9 contract remains intact. Passive/local task adapters may delegate to existing R5/R11.1/R11.5/R11.6 projections. Task types without a complete existing owner contract will remain explicit `ADAPTER_UNAVAILABLE` results.

## Acceptance criteria

R15 is complete only if an explicitly authorized, localhost-only R14 campaign can resolve real built-in owners, invoke at least one existing owner-controlled R3 path, produce only existing R2/R11-owned references, persist truthful R10.5/R14 lifecycle state, and remain fail-closed for every missing/malformed/cross-project/expired/revoked/over-budget/cancelled/timeout/owner-mismatch condition. The completed coverage includes built-in adapter unit tests, a real-R3 localhost campaign cycle, a direct assessment CLI localhost run, dispatch-context fuzzing, registry/dispatch/result benchmarks, a prohibited-egress audit, and race/full quality gates. The branch remains unmerged and R16 is not started.
