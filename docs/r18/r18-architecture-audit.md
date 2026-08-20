# R18 Architecture Audit — Continuous Assessment and Security Regression Intelligence

## Scope and branch boundary

R18 starts from the verified R17 commit `f3edb2c5d291bc7851345b06d53cc7e9eb4fc854` on `feature/r18-regression-intelligence`. `origin/main` remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`. R18 is a deterministic, project-scoped, offline comparison layer. It must not merge to `main`, start R19, execute an assessment, or alter R11.5 finding/risk lifecycle state.

> R18 describes a recorded change between two immutable assessment states. A new endpoint, changed risk band, stale correlation, incomplete task, or resolved finding is not by itself proof of exploitability, remediation, or an active revalidation.

## Verified reusable owners

| Concern | Authoritative owner and available records | R18 rule |
| --- | --- | --- |
| Scope, authorization, and egress | R1/R3/R10.5 | R18 remains offline. It invokes no client, resolver, socket, subprocess, collection path, or assessment execution. Existing R1 remains mandatory if a later distinct command can cause active work. |
| Campaign lineage and coverage | R14 `CampaignRecord`, cycles, tasks, and checkpoints | Consume exact project/campaign/scope/surface/checkpoint/task identities and recorded statuses only. R18 does not create cycles, tasks, checkpoints, or events. |
| Surface snapshots | R11.6 `attacksurface.Snapshot` and storage snapshot records | Reuse graph fingerprint, source version, node/edge counts, and project identity. Stored snapshots lack immutable per-snapshot membership, so R18 cannot infer endpoint/parameter additions from a graph record alone. |
| Findings and recorded risk | R11.5 `SecurityFindingRecord` | Reuse finding ID/fingerprint, existing severity/risk score/band/status, and safe lineage references. R18 compares existing values and never rescales, creates, suppresses, resolves, or reopens a finding. |
| Evidence verification | R17 correlation snapshots | Reuse the persisted verification, freshness, reproducibility, gap, and contradiction state. R18 does not recalculate correlation or execute validation. |
| Reporting | R16 `reportmodel`, `reporting`, and `wraith report` | R18 supplies a deterministic read-only projection. R16 remains the owner of report rendering and output safety. |

## Persistence and lineage limits

The current schema has sixteen migrations. R17 correlation snapshots are project/campaign/finding scoped and idempotent. Campaigns retain a surface snapshot reference, but the R11.6 node and edge tables are mutable project-level identities rather than an immutable membership ledger. Therefore R18 must store a compact immutable snapshot of the safe references it compares; it cannot reconstruct historical endpoint or parameter membership from the current graph.

The R18 snapshot needs project identity, safe campaign/scope/assessment/surface references, sorted compact surface subject fingerprints, existing finding risk records, R17 correlation state, deterministic coverage counts, schema/version, timestamp, and fingerprint. It must exclude bodies, payloads, cookies, credentials, authorization values, and any secret-like identifier.

## Proposed bounded model

`internal/regression` will be a pure deterministic package. It will accept a baseline and current R18 snapshot, reject cross-project or malformed/secret-bearing input, normalize sorted entries, and emit stable comparison items with category, change type, impact band, confidence, reason, safe lineage references, limitations, and fingerprint. Its input clock is explicit; it will not read a database or wall clock.

Storage and CLI adapters will be responsible only for loading existing project-scoped records, creating an explicit immutable snapshot, optionally persisting snapshots/comparisons idempotently, and rendering existing offline output formats. A CI-oriented `check` path may produce a distinct regression-detected exit code, but it remains read-only and offline.

## Rejected duplication and prohibited work

R18 rejects new HTTP, DNS, resolver, dialer, crawler, scanner, fuzzer, injection runner, validator, risk model, finding engine, campaign executor, scheduler, authentication flow, remote service, queue, dashboard backend, or report service. It must not mutate R11.5 findings, R14 state, R17 snapshots, or R16 report inputs.

## Initial acceptance criteria

R18 is acceptable only if it produces deterministic baseline/current snapshots and project-isolated comparisons; distinguishes surface, finding, risk, evidence, and coverage changes; records explicit limitations rather than inferred historical lineage; preserves secret minimization; provides stable fingerprints and idempotent persistence; supports an offline CLI and report projection; includes red/green unit and storage/CLI tests, fuzzing, benchmarks, source-level egress audit, full quality gates, documentation, feature-branch commit, and remote push. Main remains untouched and R19 is not started.
