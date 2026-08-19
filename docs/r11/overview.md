# R11 — Advanced Active Web Security Engine

R11 is a sequential program. **R11.1 through R11.4 are approved and implemented on separate feature branches.** R11.5 and R11.6 remain unstarted and require separate explicit approval.

R11.1 adds a local, deterministic Request Mutation Engine. It consumes existing project-scoped R2 endpoint and parameter identities. R5 and R6 discoveries are already represented through those R2 identities; R10 identities remain metadata-only and no credential, cookie, token, or session secret is loaded or persisted. R10.5 provides the eventual bounded run model, but R11.1 does not execute a phase or create network work.

| Approved R11.1 behavior | Explicitly excluded until a later approved stage |
| --- | --- |
| Construct immutable query, path, form, JSON, and safe-header variants. | HTTP execution, R1 evaluation, R3 dispatch, request scheduling, or new workers. |
| Emit deterministic estimates and secret-safe fingerprints. | Security signals, validation, correlation, findings, coverage claims, or reports of vulnerabilities. |
| Enforce authorization intent, project matching, bounds, and sensitive-header exclusion before candidate construction. | Authentication attacks, raw cookie handling, session replay, secret persistence, or a new asset/evidence model. |

## R11.3 update

R11.3 adds a bounded injection-test planner and an explicit active runner seam. It reuses R11.1 payload composition, R7 baseline analysis, R2 redacted observations, the caller-supplied R3 client, and R10.5 budget/rate/concurrency controls. It accepts only `GET` and `HEAD`, requires explicit authorization and active-execution opt-in, and halts after a `429` service-instability response.

| R11.3 capability | Explicit boundary |
| --- | --- |
| Immutable, profile-filtered payload registry for SQL, NoSQL, command canary, SSTI, HPP, header, and path/input signal classes. | Payload values remain memory-only; no arbitrary user payloads, destructive values, OS command execution, callbacks, or credential testing are accepted. |
| One baseline and one bounded payload request per test through R3. | The CLI is plan/dry-run only; no direct client, transport, resolver, DNS, socket, or subprocess is introduced. |
| Redacted R2 injection observations and an explicit validation submission interface. | Signals are not findings. R8 validates; R9 correlates validated evidence later. |

## R11.4 update

R11.4 turns one R11.3 signal into bounded reproduction work without equating a differential with a vulnerability. Candidate construction enforces project-local endpoint, parameter, and test identity. The runner rechecks R1 before every injected R3 dispatch, uses the existing R10.5 capacity controls, accepts only approved `GET`/`HEAD` templates, stops on `429`, and treats generic infrastructure failures as inconclusive.

| R11.4 capability | Explicit boundary |
| --- | --- |
| Deterministic candidate, response-diff, repeatability, confidence, and temporary finding-candidate models. | Confidence is not severity; no final finding, accepted lifecycle state, arbitrary payload, or raw evidence is created. |
| R8 adapter writes redacted append-only R2 validation observations. | R11.4 neither replaces R8 validation semantics nor creates another evidence store. |
| R9 adapter receives only validated evidence-backed candidates. | R11.4 does not group, deduplicate, correlate, or claim root cause; R9 remains authoritative. |
