# R13 Active Web Assessment Engine Audit

**Verified base:** `5833d77` on `feature/r12-integration-hardening`. R13 work is on `feature/r13-active-assessment`; `origin/main` remains `42cb8b2` and is not changed.

R13 is an execution/integration layer, not a replacement scanner. It must use R10.5 as the lifecycle and shared-control owner, R1 for authorization, R3 for all target-web transport, R2 for redacted append-only evidence, and existing R7/R11.3/R11.4/R11.5/R11.6 components for their respective bounded semantics.

| Existing owner | Verified reusable contract | R13 boundary |
| --- | --- | --- |
| R1 policy | Project scope, authorization, target normalization, deny/expiry/revocation, and per-request decision boundary. | Assessment planning cannot infer authorization from discovery; active adapters recheck policy before R3 dispatch. |
| R2 evidence | Stable project-local asset/endpoint/parameter identities and redacted append-only observations. | No request body, cookie, token, authorization header, credential, or raw payload persistence. |
| R3 HTTP | Injected policy-aware client, destination controls, redirects, bounded response, pacing, concurrency, cancellation. | No direct client, DNS, socket, TLS, redirect, or resolver implementation in R13. |
| R10.5 pentest | `BuildPlan`, ordered phases, run lifecycle, budget/concurrency/rate controls, resume storage and reports. | R13 extends existing plan/lifecycle vocabulary; it does not create a second orchestration database or independent limiter. |
| R7/R11.3 | Bounded fuzz and injection plans/runners with baseline analysis and signal-only output. | R13 selects existing plans and passes shared controls; raw responses never become findings. |
| R11.4/R9/R11.5/R11.6 | Validated candidate, correlation, local finding/risk, graph/campaign models. | R13 preserves validation → correlation → finding → risk/graph ordering. |
| R12 | Temporary SQLite/isolated-project CLI smoke patterns and CI quality gates. | R13 uses localhost-only fixtures and does not add external integration. |

## Existing execution and missing seams

`pentest.BuildPlan` currently supports `recon`, `standard`, `deep`, and `authenticated` profiles with deterministic module ordering. `Orchestrator.Execute` executes registered phase functions serially with shared R10.5 budget, concurrency, and rate controls. The CLI already offers `pentest plan`, list, and resume, but it does not expose a complete active assessment plan/task model, immutable scope snapshot, or phase adapter registry suitable for R13’s assessment terminology.

The R13 implementation must therefore be a narrow `internal/assessment` planning/adapter package plus a `pentest` profile/module extension. Its first increment will construct deterministic, memory-only assessment scope snapshots and task graphs, validate dependencies and budgets, support plan/dry-run output, and expose an explicit injected execution seam. It must not use live modules unless the caller supplies R1/R3/R10.5-backed adapters.

## Security and performance risks

| Risk | Required mitigation |
| --- | --- |
| Scope drift or expiration | Scope snapshot records project, profile, authorized state, target, limits, and expiry. Invalid/expired snapshots fail closed. |
| Duplicate/bypassed execution | Deterministic task IDs, explicit dependency graph, shared R10.5 controls, and durable owner-owned run state. |
| Budget/rate divergence | No local budget manager or rate limiter; execution dependencies receive existing R10.5 controls only. |
| Secret leakage | Authentication context is an opaque reference only; terminal/JSON models contain no credential material. |
| Unsafe test traffic | All active tests use injected localhost-only R3 fixtures; plan tests perform zero network I/O. |
| Overstated results | Tasks generate signals/evidence, never direct findings. R11.4/R9/R11.5 remain lifecycle owners. |

## Deliberate R13 limits

R13 excludes arbitrary command execution, destructive payloads, credential attacks beyond existing explicitly gated R10 behavior, direct transport, unbounded queues/workers/retries, external orchestration services, database dumping, post-exploitation, new exploit classes, main merges, and R14.
