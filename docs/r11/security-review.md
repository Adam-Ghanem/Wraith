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
