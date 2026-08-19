# R13 Active Web Assessment Engine

R13 adds a **deterministic assessment planning and adapter-execution layer** above existing Wraith components. It does not replace R1 policy, R2 evidence, R3 transport, R10.5 lifecycle/resource controls, or R11 validation/finding/risk/graph ownership.

| Capability | R13 behavior | Boundary retained |
| --- | --- | --- |
| Scope snapshot | A plan requires project, target, scope version, explicit authorization, bounded profile/limits, and an expiry. | An expired or missing authorization scope fails closed before task execution. |
| Profiles | `safe`, `standard`, and `deep` choose deterministic bounded task sets. Safe omits fuzz and injection. | No profile disables R1, R3, project isolation, duration, requests, concurrency, or rate bounds. |
| Tasks | Stable project-scoped task IDs represent crawl, inventory, JS, baseline, discovery, mutation, fuzz, injection, validation, correlation, finding, risk, surface, and report sequence. | Dependencies are explicit and malformed/cross-plan graphs are rejected. |
| Execution seam | `assessment.Execute` requires the existing R10.5 budget, concurrency controller, and global rate limiter plus an injected task adapter. | R13 contains no HTTP client, DNS resolver, socket, redirect/TLS logic, scanner, payload generator, or local finding creator. |
| CLI plan | `wraith pentest assessment plan TARGET --project PROJECT --authorized --scope-version VERSION` produces only an in-memory deterministic plan. | It performs zero network I/O and accepts no secrets/credentials. |

## Execution ownership

The injected task adapter is responsible for invoking the approved existing component for each task: R4/R5/R6 for acquisition/intelligence, R7/R11.3 for bounded active signals, R11.4/R9/R11.5/R11.6 for validation through graph lifecycle. Every network-capable adapter must recheck R1 and dispatch only through R3. The R13 package cannot bypass those controls because it owns neither a client nor a transport.

## Current deliberate limitation

R13 provides the fail-closed shared plan/task model and adapter seam, plus no-network CLI plan output. It does not silently wire live crawler/fuzz/injection/validation adapters into a new automatic pipeline because each requires configuration-specific R1 scope, R3 client, R2 evidence, R10.5 controls, and R11 lifecycle dependencies. Such a wiring belongs to an explicit approved adapter configuration rather than an implicit active command.

R13 also excludes external queues, distributed workers, new authentication mechanisms, credential persistence, arbitrary execution, destructive payloads, new exploit classes, main merge, and R14.

## R13.2 execution handoff

R13.2 supplies the bounded synchronous lifecycle below this planner. It validates the complete plan again, resolves only R13.1-registered owners, rechecks authorization before dispatch, shares R10.5 controls, propagates cancellation and task deadlines, and writes project-scoped secret-free lifecycle state through existing R10.5 storage. Its `run --dry-run` command validates scope, plan, owner bindings, budgets, and authorization without invoking an adapter or writing an execution lifecycle record. R13.2 continues the deliberate limitation above: it does not manufacture a real crawler, fuzzer, injection, validation, correlation, finding, or report adapter from incomplete configuration.
