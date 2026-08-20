# R14 — Security Review

## Review conclusion

R14 is a bounded orchestration addition. Its data model, storage, and CLI do not introduce an egress primitive or duplicate an existing security authority. The only execution handoff is through R13.2, which already relies on R13.1 registry ownership and R10.5 shared controls.

| Boundary | Review result |
| --- | --- |
| R1 authorization | Campaign create and run load the active project scope/version through the existing evaluator. R13.2 rechecks authorization again before execution and adapter dispatch. |
| R3 transport | No R14 HTTP client, resolver, socket, TLS, redirect, proxy, browser, or subprocess exists. Active owner work remains outside R14. |
| R10.5 controls | A cycle constructs one shared budget, concurrency controller, and rate limiter; R14 does not maintain an alternate request counter. |
| R11.6 graph | R14 persists an immutable project-scoped snapshot reference rather than copying graph semantics or treating edges as attack paths. |
| R13.2 execution | R14 delegates the filtered plan only to the engine; it does not invoke an adapter directly. Missing owner implementations fail closed. |
| Persistence | Campaign tables all include `project_id`; storage API queries bind project and identifier; SQLite foreign keys constrain cycles, tasks, checkpoints, and events. |
| Secrets | Campaign references reject credential-like values. Checkpoints contain identifiers, bounded statuses, timestamps, and deterministic fingerprints only. Event metadata is fixed to `{}`. |
| Dry run | Regression coverage proves that dry-run creates no campaign cycle, R10.5 run, or checkpoint and does not invoke adapter-owned behavior. |
| Findings | Campaign state records execution coordination only. It does not create findings, risk scores, or evidence. |

## Test evidence

The R14 regression suite covers explicit campaign/task terminal transitions, cross-project surface rejection, checkpoint tampering, completed-task replay prevention, explicit eligible resume-cycle filtering, R1 pre-handoff denial, dry-run state preservation, project-scoped SQLite persistence, checkpoint lookup, temporary-SQLite create/status/run behavior, and zero-lifecycle-write dry run. Fuzz targets exercise checkpoint integrity and secret-like creation context; the benchmark covers local campaign construction/cycle planning only.

## Remaining risk and condition for expansion

The durable resume/pause/cancel/scheduling CLI surface remains intentionally deferred. It must not be added until each installed real owner adapter supplies cancellation and persisted lifecycle semantics, supports R1/R3/R10.5 rechecks, and passes localhost-only end-to-end coverage. No R14 component should make a schedule or checkpoint an authorization grant.
