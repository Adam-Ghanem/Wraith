# T7 master-prompt reconciliation

## Starting point

The historical `feature/t7-data-classification-governance` implementation has been merged normally into `feature/t7-governance-reconciled`, which starts at the protected T3–T6 `main` merge commit. The historical branch remains unchanged. Its current authority, `internal/dataclassification`, already supplies bounded secret screening, deterministic redaction, safe URL/header/JSON projections, evidence/report/export integration, safe governance audit events, and migration `025_t7_data_governance.sql`.

The supplied master prompt requires broader central governance than the imported baseline supplies. In particular, the baseline has no immutable project-scoped policy records, no explicit consumer/classification decision model, no retention record or lifecycle evaluation, and no policy/retention command family. These are the confirmed gaps to close. The implementation must not replace the existing data-classification package or recreate T1–T6 authority.

## T7 extension boundary

The extension adds `internal/datagovernance` as the central pure decision authority. `internal/dataclassification` remains the sole raw-value screening and redaction authority. The new package accepts only already-safe identifiers, classifications, policy data, consumer intent, and timestamps. It has no network, filesystem, database, subprocess, resolver, transport, scheduler, or raw-secret storage capability.

| Authority | Owns | T7 relationship |
|---|---|---|
| T1 authorization | Authorization lifecycle validity | Governance mutations validate an existing T1 record; T7 creates no authorization state. |
| T2 scope | Target scope | Applied only when a governed operation is target-related; governance policy records cannot expand scope. |
| T3/T4 | Active execution assurance and derived trust | Remain authoritative for active task paths; T7 adds no trust predicate or context. |
| T5/T6/R3 | Outbound policy, enforcement, and transport | T7 makes a pure egress representation decision only; it never dispatches data. |
| `dataclassification` | Secret screening and canonical redaction | Reused for all policy identifiers, subject references, audit records, and governed projections. |
| `datagovernance` | Policy, consumer decision, retention calculation, and integrity checks | New single source of governance decisions. |

## Governance model

The canonical classification order is `public < internal < sensitive < restricted < secret`. The `restricted` level permits only metadata-safe projections; `secret` is never raw-persisted and is blocked or redacted by the existing classifier before a governance decision is created.

Policies are immutable and project-scoped. A policy contains a version, ordered classification/consumer rules, retention duration, hold state, timestamps, and a SHA-256 fingerprint over canonical JSON. Duplicate rules, unknown consumers, malformed versions, invalid duration, cross-project references, secret-like identifiers, and forged fingerprints are rejected. A policy record is not trusted merely because it is stored; its fingerprint is recomputed when it is read or used.

The decision authority returns only `allow`, `allow_redacted`, `allow_hashed`, `allow_metadata_only`, `deny`, `expire`, or `delete`, with a stable reason code, policy version, classification, subject type, project, UTC timestamp, and canonical fingerprint. Consumer rules are explicit for local storage, technical reports, executive reports, CLI output, JSON/Markdown/HTML exports, audit logs, analytics, and egress. Egress decisions govern representation only; the existing T5/T6 gateway remains the only egress enforcement/dispatch path.

Retention evaluation is deterministic and read-only. It returns active, held, expired, deletion-eligible, or denied state from a policy-derived retention record. There is no background deletion worker and ordinary reads never delete data. The first purge surface is a dry-run-only, T1-validated plan; any destructive executor remains explicitly unavailable.

## Storage and CLI design

Migration `026_t7_governance_authority.sql` will add additive, project-scoped policy, classification-record, decision, retention-record, and event tables. All reads are parameterized and filter on `project_id`; all records are revalidated after hydration. Existing migration 025 data remains unchanged and is recorded as `legacy-governed` rather than silently upgraded.

The reconciled CLI family is `wraith governance`. It provides policy create/list/show, classify, inspect, check, retention check/list/purge --dry-run, and audit. Policy creation and purge-plan creation require an existing valid T1 authorization record for the declared project/scope and explicit `--authorized` acknowledgement; the command performs no target access or egress, so it does not invent a T2/T3/T4/T5/T6 bypass. Read-only commands do not write lifecycle state. Unsafe raw secret values are rejected at the CLI boundary and are never echoed in errors.

## Test-first acceptance matrix

The extension begins with failing pure tests for classification ordering, canonical policy fingerprints, duplicate-rule rejection, secret-free input, consumer restrictions, project mismatch, stale/forged policy rejection, and retention decisions. It then adds storage migration/restart/idempotency/isolation tests, CLI authorization/dry-run tests, local fuzz targets for policy parsing/decision/retention, and benchmarks for decision and projection paths. Existing evidence, report, analytics, and T5/T6 integration tests remain the compatibility proof; T7 does not claim universal migration of every legacy producer.
