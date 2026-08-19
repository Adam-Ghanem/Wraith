# R11.1 Security Review

| Audit | Result |
| --- | --- |
| R1/R3 bypass | No execution path exists in R11.1. Any later executor must evaluate R1 and dispatch exclusively through R3. |
| Direct HTTP, DNS, socket, subprocess | None in `internal/requestmutation`. The package only parses and transforms local in-memory values. |
| Project isolation | The plan requires matching input project, endpoint project, parameter project, and endpoint identity. |
| Secret handling | Request templates are memory-only and excluded from JSON output. Sensitive header names are rejected; fingerprints use hashes rather than raw body output. |
| Request/budget/rate/concurrency bypass | R11.1 creates no requests or workers. Its variant-count, value-size, body-size, and JSON-depth bounds constrain later candidate consumption. |
| Cancellation and goroutine safety | R11.1 performs synchronous local transformations and starts no goroutine. |
| Injection or destructive behavior | Candidate values are generic deterministic boundaries only. The package does not execute payloads, commands, or mutations against a target. |

The remaining review work belongs to later approved R11 stages: R1/R3 execution integration, global R10.5 budget consumption, health monitoring, active evidence, localhost integration, validation, correlation, and reporting.

## R11.2 update

| Audit | Result |
| --- | --- |
| Passive planning | `Build` performs only bounded local normalization, R2/R5 identity reuse, provenance merging, and safe local-wordlist parsing. |
| R3-only verification | `Verify` accepts an existing `httpengine.Client`; it creates no HTTP client, resolver, socket, or subprocess. Requests are explicit `HEAD` calls with redirect following disabled. |
| R1 and capacity controls | The R3 client remains the policy boundary; `Verify` additionally requires authorization intent and consumes R10.5 global budget, rate, and concurrency controls before each request. |
| Sensitive data | Candidate values reject secret-like strings and sensitive paths. Verification evidence has no request body, headers, cookies, candidate value, or credential fields and is marked redacted. |
| Project isolation | Build requires an inventory for the requested project and verification rejects malformed/non-URL candidates before dispatch. |
| Remaining limit | No persistent candidate store or pentest phase registration is introduced; R11.2 is a bounded command/library slice and does not begin R11.3. |

## R11.3 update

| Audit | Result |
| --- | --- |
| R1/R3 bypass | `Run` accepts only an injected `httpengine.Client`; it does not construct a client, transport, resolver, or request path. The injected R3 client remains responsible for R1 and destination controls. |
| Request and method bounds | Each planned test uses a baseline plus one registered payload request; only `GET` and `HEAD` are accepted. Unsafe methods and malformed/cross-project plans are rejected before dispatch. |
| Capacity, cancellation, and health | Baseline and payload dispatch reuse R10.5 budget, global rate, and concurrency controls. The runner observes its context and returns `ErrServiceInstability` immediately on `429`. |
| Payload and secret handling | The registry is immutable and bounded. Payload values use `json:"-"`; only identifiers and fingerprints reach output. Redacted observations omit request values, bodies, cookies, and authorization data. |
| Direct execution hazards | No R11.3 source imports `os/exec` or opens a direct HTTP/DNS/socket path. Command-class coverage is a response canary only; it cannot execute a local or remote command. |
| Finding lifecycle | R11.3 emits signals and may submit them to an explicit validation interface. It has no local finding creator, and the run result stays at `FindingsCreated: 0`. R8 owns validation and R9 owns later correlation. |
| Remaining limit | There is no R10.5 phase registration, automatic R8 adapter, R9 correlation invocation, persistent injection-test store, or reporting layer. These remain separately approved follow-on work. |

## R11.4 update

| Audit | Result |
| --- | --- |
| R1/R3 enforcement | Every runner dispatch calls a required policy-recheck interface first, then an injected R3 client. The package creates no transport, DNS, resolver, or socket path. |
| Resource bounds | Profiles send one, two, or three baseline/mutation pairs. Every request consumes the R10.5 budget, global rate limiter, and concurrency slot. |
| Stability and false positives | `429` halts immediately. Generic 5xx changes are instability, not security evidence. Only repeatable security-relevant differentials become validated. |
| Sensitive data | Payload values remain memory-only. Candidate/result/finding-candidate serialization excludes signal metadata, raw payloads, cookies, authorization material, and response bodies. |
| R8/R9 lifecycle | R8 owns observed validation evidence and R2 persistence. R11.4 sends only validated evidence-backed temporary candidates to R9, which remains correlation authority. |
| Remaining limit | No durable lifecycle store, R10 identity-session binding, R10.5 phase registration, safe resume, or report adapter is added. |

## R11.5 update

| Audit | Result |
| --- | --- |
| Network/process boundary | `internal/riskintelligence` has no HTTP, DNS, socket, transport, resolver, process, or shell behavior. It is local deterministic data transformation only. |
| Validated-only intake | Assessment requires matching validated/repeatable R11.4 result, evidence references, and a correlation ID; rejected/inconclusive candidates fail closed. |
| Score and lifecycle | Versioned `r11.5-v1` factors/bands are deterministic and bounded. Invalid transitions, cross-project suppression, and expired suppression fail closed. |
| Storage/output minimization | Project-local SQLite records are indexed and history is append-only. Local output omits internal candidate fingerprints and raw secret-bearing material. |
| Remaining limit | The named `r11.5_risk` phase has no automatic ingestion/active adapter, no full report integration, analyst mutation CLI, or resume semantics. |

## R11.6 update

| Audit | Result |
| --- | --- |
| Execution boundary | R11.6 is a local graph/campaign projection only. It imports no direct HTTP, DNS, socket, resolver, shell, or subprocess path. |
| Graph integrity | Deterministic project-scoped nodes/edges reject cross-project and orphan relationships. Snapshot fingerprints exclude timestamps and task budgets are bounded. |
| Lifecycle boundary | The registered `r11.6_attack_surface` phase does not execute work automatically. Campaign output is dry-run planning; R10.5/R1/R3 remain authoritative. |
| Remaining limit | Rich source adapters, graph membership history, active phase execution, reports, analyst lifecycle mutation, and R12 are deferred. |
