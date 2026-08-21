# T8 Central Data Classification and Protection Authority

## Starting state and ownership

`feature/t8-data-classification-protection` begins at protected `main` commit `eab2809` and carries the verified T7 reconciliation through a normal feature-branch-only merge. This keeps `main` untouched while preventing T8 from recreating T7 functionality.

T8 adds `internal/dataprotection`, a pure protection-decision authority. It does not replace `internal/dataclassification`, which owns bounded raw-value screening and deterministic redaction, or `internal/datagovernance`, which owns project-scoped consumer policy and retention. T8 also does not recreate T1 authorization, T2 scope, T3/T4 assurance, T5/T6 egress, or R3 transport.

| Authority | Owner | T8 role |
|---|---|---|
| Raw-value secret screening and redaction | `dataclassification` | Reused before descriptor fingerprinting, snapshot persistence, rendering, audit, or CLI output. |
| Consumer policy and retention | `datagovernance` | Revalidated and evaluated as a prerequisite to every protection decision. |
| Authorization lifecycle | T1 | A storage/CLI adapter validates an existing T1 record for protected mutations; no new authorization records are created. |
| Scope and active trust | T2–T4 | Required only where a T8 caller handles target-derived active-assessment data; T8 accepts safe references and does not evaluate targets. |
| Outbound transport and egress | R3/T5/T6 | T8 can decide a representation but cannot dispatch it. |

## Protection model

The existing T7 classification vocabulary is retained unchanged: `public < internal < sensitive < restricted < secret`. T8 does not add caller-defined classifications. `secret` never becomes raw-persisted or rendered: the existing classifier redacts or rejects it before a T8 descriptor can be constructed.

T8 defines a closed, versioned set of protection profiles: `public-output`, `internal-output`, `technical-output`, `executive-output`, `audit-event`, `local-persistence`, and `export`. Each profile defines a maximum admissible classification, whether redaction is mandatory, the permitted field classes, whether identifiers/evidence references are permitted, and whether persistence or local-process egress representation is permitted. No profile is caller-defined.

`Descriptor` contains only project-scoped safe references and metadata: object type, object ID, effective classification, allowed field classes, creation/expiry timestamps, source reference, scope reference, governance-policy fingerprint, and a canonical SHA-256 fingerprint. It never carries headers, cookies, tokens, credentials, raw evidence, or arbitrary raw JSON.

`Evaluate` is pure. It validates the descriptor and profile fingerprint, revalidates the supplied T7 policy and T7 decision, verifies project and governance-policy binding, applies deterministic classification aggregation, and returns an allow/deny/redact/metadata-only decision with a reason, field allowlist, forbidden field classes, effective classification, and fingerprint. It has no database, filesystem, network, environment, subprocess, or time-source side effect; callers supply UTC time explicitly.

## Snapshot and persistence boundary

Migration `027_t8_data_protection.sql` will add only immutable, project-scoped protection decision and protection snapshot records. A snapshot contains safe descriptor references, profile/version, T7 governance-policy fingerprint, T8 decision fingerprint, creation/expiry timestamps, and its own fingerprint. New state creates a new snapshot; records are never updated to re-activate expired or revoked state. Existing T7 append-only audit events are reused for T8 decision and snapshot lifecycle entries rather than introducing a duplicate audit authority.

All storage reads filter by `project_id`, use parameterized queries, strictly decode bounded canonical representations, and reconstruct/revalidate records before use. No raw values, uncontrolled JSON, credentials, authorization tokens, or session material are stored.

## Integration and CLI

R16 already routes terminal, JSON, Markdown, and HTML through one validated report snapshot. T8 will consume that safe representation rather than rewrite reporting: a single profile decision is applied before render/output writing. Existing `export-fixtures` remains T6-blocked and does not gain a new output route. R21 analytics projections use aggregate-only profiles before render.

The existing `wraith data` family will gain `validate`, `protect`, `redact`, and `snapshot` operations; its existing `classify` and T7 policy commands remain their current owners. Protected mutating operations require an explicit project, an existing valid T1 authorization record, a safe scope reference, and an existing T7 policy version. `--authorized` remains an acknowledgement only and never substitutes for the T1 record.

## Test-first acceptance criteria

The first tests cover deterministic maximum aggregation, profile restrictions, forced redaction, secret rejection, forged descriptor/policy/decision fingerprints, missing/expired T7 governance, project mismatch, stale descriptor, immutable snapshot behavior, cross-project storage reads, T1-bound protected CLI operations, and no direct transport imports. Subsequent tests cover report and analytics profile projection, output-path safety, migration/restart/idempotency, fuzzed descriptor/parser inputs, and bounded benchmarks.
