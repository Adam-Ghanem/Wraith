# T4 Security Review

| Threat | T4 control | Residual boundary |
|---|---|---|
| R1 acknowledgement is confused with ownership proof | Non-dry execution requires T1/T2/T3-derived context. | R1 remains a required operator acknowledgement. |
| A stale authorization or scope is reused | Context derivation reloads authority and reruns T3 classification per task. | T1/T2 remain the authoritative lifecycle and scope owners. |
| A task is substituted after planning | Context binds project, assessment, task identifier, and task fingerprint. | Task planning validity remains owned by R13. |
| A campaign invokes work outside its identity | Campaign identifier is bound into the execution request and context. | Campaign state validation remains owned by R14. |
| An adapter is invoked without central trust | Engine and adapter registry independently reject missing or invalid context. | Adapter behavior and per-request controls remain R15 responsibilities. |
| A forged or cross-project context is replayed | Canonical fingerprint and project/scope/task validation fail closed. | Local database tamper detection remains bounded by existing SQLite controls. |
| T4 leaks sensitive values into diagnostics | Context carries only identifiers and fingerprints; adapter and execution events use fixed reason codes. | Existing evidence redaction policy remains applicable. |

## Egress and capability audit

T4 adds no HTTP client, DNS resolver, socket, subprocess, shell-out, scheduler, worker, or remote control plane. `internal/trustcontext` performs no I/O. The existing R3 engine remains the only active transport owner and continues to apply policy, redirect, and resolved-IP checks.

## Explicit non-claims

T4 does not verify external legal ownership, does not perform exploit validation, does not make authorization perpetual, does not repair compromised local storage, and does not provide remote execution or a hosted control plane.
