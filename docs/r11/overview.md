# R11 — Advanced Active Web Security Engine

R11 is a sequential program. **R11.1 and R11.2 are approved and implemented on separate feature branches.** R11.3 through R11.6 remain unstarted and require separate explicit approval.

R11.1 adds a local, deterministic Request Mutation Engine. It consumes existing project-scoped R2 endpoint and parameter identities. R5 and R6 discoveries are already represented through those R2 identities; R10 identities remain metadata-only and no credential, cookie, token, or session secret is loaded or persisted. R10.5 provides the eventual bounded run model, but R11.1 does not execute a phase or create network work.

| Approved R11.1 behavior | Explicitly excluded until a later approved stage |
| --- | --- |
| Construct immutable query, path, form, JSON, and safe-header variants. | HTTP execution, R1 evaluation, R3 dispatch, request scheduling, or new workers. |
| Emit deterministic estimates and secret-safe fingerprints. | Security signals, validation, correlation, findings, coverage claims, or reports of vulnerabilities. |
| Enforce authorization intent, project matching, bounds, and sensitive-header exclusion before candidate construction. | Authentication attacks, raw cookie handling, session replay, secret persistence, or a new asset/evidence model. |
