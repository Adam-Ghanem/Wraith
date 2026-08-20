# T1 — Authorization Lifecycle Design

## Purpose

T1 introduces a durable, project-scoped authorization **record lifecycle**. It does not claim to prove ownership of an arbitrary target. A record captures an operator's explicit, time-bounded authorization assertion and its safe evidence reference; later phases will bind this lifecycle to the centralized scope and egress authorities.

## Ownership boundaries

| Concern | Authoritative owner | T1 role |
|---|---|---|
| Existing R1 target-rule semantics | `internal/policy` | Unchanged; T1 does not reimplement scope matching. |
| Network transport | R3 | Unchanged; T1 has no network I/O. |
| Active-assessment lifecycle | R13–R15 | Unchanged; T1 supplies a future validation input only. |
| Authorization-record lifecycle | `internal/authorization` and storage adapter | Create, validate, list, show, revoke, canonical fingerprinting. |

## Record contract

Each record has a project ID, subject, opaque scope reference, authorization type, evidence reference, creator reference, UTC issuance/expiry timestamps, optional revocation timestamp, status, schema version, and canonical SHA-256 fingerprint. The record stores **references only**: passwords, tokens, cookies, private keys, credential-bearing URLs, and secret-like values are rejected.

An authorization is valid only when its canonical fingerprint matches, its project and requested scope match exactly, its persisted status is `active`, it is not revoked, and the current UTC time precedes expiry. Any malformed, forged, expired, revoked, cross-project, or mismatched-scope record fails closed.

## Compatibility and migration

Existing `--authorized` flags remain unchanged during T1. The new CLI requires `--authorized` for create and revoke because those actions are explicit operator attestations, but it does not retroactively alter legacy active-command behavior. T2 will establish the single scope authority; T3 will apply the lifecycle record to centralized egress governance.

## Test contract

The implementation must demonstrate deterministic fingerprints; required expiry; exact project/scope binding; expiry and revocation denial; malformed/forged record rejection; no secret-like reference persistence; storage project isolation; CLI authorization gates; safe output paths; bounded fuzzing; and a benchmark for validation.
