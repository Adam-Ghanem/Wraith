# T4 Baseline Audit — Production Trust Enforcement

T4 begins from the merged `main` baseline that contains T1 authorization lifecycle, T2 scope authority, and T3 security-trust hardening. This audit records the active ownership boundary before enforcement changes.

| Concern | Existing owner | T4 disposition |
|---|---|---|
| Operator acknowledgement | R1 CLI flags | Retained as acknowledgement only; never treated as ownership proof. |
| Authorization lifecycle | T1 `authorization.Record` and storage | Revalidated for every derived T4 context. |
| Target and scope decision | T2 `scope.Version` and `scope.Evaluate` | Revalidated before deriving T4 context. |
| Execution eligibility | T3 `securitytrust.Classify` | Required at `execution_eligible` assurance. |
| Dispatch and budgets | R13.2 `assessmentexec` | Requires T3 gate and fresh T4 context before every adapter dispatch. |
| Adapter contract | R13.1/R15 `assessment.TaskContext` | Receives only a secret-minimized derived context; rejects a missing or forged context. |
| Network destination policy | R3 `httpengine` and policy gateway | Unchanged; T4 neither owns nor bypasses destination, redirect, or IP rechecks. |
| Campaign coordination | R14 | Propagates campaign identity into the derived context. |
| Authorization audit | T3 append-only authorization audit storage | Existing lifecycle audit remains authoritative; execution summaries record trust-context denial events without raw values. |

> T4 does not create authorization state, scope state, a transport, a resolver, a socket, a subprocess, a scheduler, a worker, a credential store, or a new scanning capability.

The only legacy execution helper that could dispatch without derived trust is now rejected at the adapter boundary. R1-only state remains usable for dry-run planning where no adapter is dispatched, but non-dry active execution requires T1/T2/T3 lineage.
