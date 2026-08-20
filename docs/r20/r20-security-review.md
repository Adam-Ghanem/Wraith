# R20 Security Review — Governance Operations and Audit State

## Scope

This review covers R20’s local governance model, SQLite migration `019_r20_governance.sql`, `wraith govern` command family, R16 report projection, CI status semantics, and supporting R19 evaluation integrity validator. It excludes active assessment execution because R20 introduces none.

## Review result

The reviewed R20 implementation is a deterministic, project-scoped, offline governance layer. No unresolved release blocker was identified after the hardening tests and quality checks described below. The implementation intentionally leaves approval identity, remediation proof, scheduled assessment, remote audit replication, and action execution outside scope.

| Area | Control | Review outcome |
| --- | --- | --- |
| Egress | `internal/governance`, R20 storage, and `internal/cli/govern.go` contain no HTTP client, resolver, dialer, listener, socket, or subprocess path. | Pass. R20 only uses local SQLite and in-memory deterministic logic. |
| Project isolation | All R20 reads/writes use project-bound parameterized SQLite queries; R19 action/evaluation and R18 comparison references are loaded under the selected project. | Pass. Cross-project state/action access is rejected or absent rather than joined. |
| Reference integrity | Persisted R19 evaluation JSON is revalidated by `continuousassessment.ValidateControlEvaluation`; R20 state, decision, and event fingerprints are recomputed before use. | Pass. Forged decision/action/state/event content fails closed. |
| Lifecycle integrity | Pure transitions validate predecessor/next-state pairs; storage uses expected-state fingerprint matching and one transaction for state plus audit writes. | Pass. Stale/concurrent transitions conflict; duplicate deterministic events are idempotent. |
| Audit durability | Decision/event records are append-only in migration 019; a forced event-insert failure rolls back the new state. | Pass. No successful state transition survives without its corresponding audit append. |
| Secret handling | Identifiers, actor, reason, status fields, persisted JSON, and report fields are bounded and screened for credential-like markers. | Pass. Secret-like inputs are rejected instead of stored or rendered. |
| CI semantics | Governance failure, invalid input, and classified internal error are distinct from successful output. Strict `unknown`, stale, failed, and unresolved-high posture fails closed. | Pass. Exit codes are `0/1/2/3`. |
| Reporting | R16 reportmodel normalization fingerprints governance data; executive renderers omit technical reason/action lineage; technical renderers escape it. | Pass. No second renderer or report-time recalculation was introduced. |

## Abuse cases covered

| Abuse case | Deterministic response |
| --- | --- |
| A caller supplies another project’s action ID. | Project-filtered R19 action/evaluation lookup rejects the reference. |
| A caller replays a transition after state changed. | The exact expected predecessor no longer matches; the operation returns a governance conflict with no extra event. |
| Two callers transition the same recommendation simultaneously. | Exactly one state/event transaction commits; the competing transition returns a deterministic conflict. |
| An event insert fails after a state write begins. | The entire transaction rolls back, leaving no persisted new state. |
| Persisted R19 or R20 JSON is manually altered. | Fingerprint/integrity validation rejects it before governance or report projection. |
| A reason/actor contains a credential-like marker. | Validation rejects it; the value is not persisted or rendered. |
| No R19 evaluation exists. | `status` reports explicit `unknown`; strict `check` fails rather than treating absence as healthy. |
| An operator treats `completed` as remediation proof. | R20 records only the decision and documents that it is not evidence of remediation or security. |

## Verification evidence

The implementation includes pure lifecycle/status tests, R19 evaluation-integrity tests, SQLite isolation/idempotency/restart/rollback tests, concurrent expected-state tests, CLI command/exit/status/history tests, R16 executive-versus-technical renderer tests, report projection tests, fuzz targets, and a lifecycle benchmark. The source-level egress audit searches R20 core/storage/CLI paths for prohibited network, resolver, socket, listener, and subprocess primitives.

## Residual risks and required future review

Local SQLite audit history is not a distributed tamper-proof log and R20 has no authenticated operator identity. A decision can be operationally meaningful only within the local repository/user context. Before multi-user approval, remote synchronization, retention controls, notification, scheduled reassessment, or remediation execution, the project must add a separate identity, authorization, retention, audit-protection, cancellation, budget, and R1/R3/R10.5/R13–R15 delegation design.
