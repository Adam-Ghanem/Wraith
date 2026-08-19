# R13 Security Review

| Review area | Result |
| --- | --- |
| Authorization and expiry | Scope creation requires explicit authorization and a future expiration. Executor rechecks authorization/expiration before each task. |
| Transport | R13 has no network primitive. Any task adapter must receive existing R1/R3/R10.5-controlled dependencies externally. |
| Resource limits | Plan limits reject zero, negative, oversized duration/request/concurrency/rate values. Executor requires the existing shared R10.5 controls, not a second limiter. |
| Project isolation | Assessment/task/scope identities include the selected project. Dependency validation rejects cross-assessment/cross-project task references. |
| Secrets | Plans contain opaque metadata only and CLI plan output accepts no credential/cookie/token/header field. |
| Findings lifecycle | R13 delegates. It does not turn raw signals into findings; validation, correlation, findings, risk, and graph remain R11.4/R9/R11.5/R11.6 responsibilities. |
| Failure and cancellation | Executor honors context cancellation, skips dependency-blocked work with explicit reason, and fails scope expiration closed. |

No new direct HTTP, DNS, socket, subprocess, credential, persistence, report-rendering, or destructive-testing path is introduced by R13.
