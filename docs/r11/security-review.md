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
