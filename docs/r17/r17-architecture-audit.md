# R17 Architecture Audit — Evidence Correlation and Finding Verification

## Scope and branch boundary

R17 starts from the completed R16 commit `256e27b228541482161119ada3d637f6926ca00e` on `feature/r17-evidence-verification-loop`. `origin/main` remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`. R17 is a bounded, deterministic, project-scoped analysis slice. It may correlate existing local records and render their verification state; it must not merge to `main`, start R18, execute an assessment, or mutate an existing owner’s lifecycle state.

> R17 is evidence intelligence, not an active capability. A verification state is not a severity, risk score, finding lifecycle transition, authorization decision, or assertion that a vulnerability exists.

## Verified reusable owners

| Concern | Authoritative owner and available records | R17 rule |
| --- | --- | --- |
| Authorization and egress | R1, R3, and R10.5 | R17 makes no authorization decision and has no HTTP client, DNS resolver, socket, budget, limiter, concurrency controller, redirect path, or subprocess. |
| Canonical lineage subjects | R2 `evidence.WebAsset`, `Endpoint`, `Parameter`, and append-only `Observation` | Reuse project-local asset, endpoint, parameter, observation, source, subject, and time identities. Observations remain redacted bounded metadata; no body, payload value, credential, cookie, or header is copied. |
| Validation and repeatability | R11.4 `ValidationResult` / `FindingCandidate` | Consume only existing validation ID, status, repeatability, confidence, and safe evidence references. R17 must not recreate validation or convert a signal into a finding. |
| Findings and risk | R11.5 `SecurityFindingRecord` | Reuse stored finding ID, project, endpoint, parameter, asset, validation, correlation, evidence references, lifecycle, timestamps, and existing risk fields. R17 must not create, suppress, resolve, rescore, or change a finding. |
| Surface intelligence | R11.6 graph and snapshots | Use the same exact finding-to-asset/endpoint/parameter/observation vocabulary. A stored snapshot has metadata but no historical membership ledger, so R17 must report this as unavailable rather than reconstruct current graph membership. |
| Assessment execution | R13/R13.2 and R10.5 lifecycle records | Use existing bounded task status and secret-free result/lifecycle envelopes only when an exact stored relationship exists. No dispatch, replay, or lifecycle write belongs in R17. |
| Campaign execution | R14 `CampaignRecord`, cycle, task, checkpoint, and event rows | Reuse exact project/campaign/cycle/task IDs, status, result reference, and timestamps. The schema has no direct finding-to-task or observation-to-task foreign key; an absent exact link is an explicit gap. |
| Reporting | R16 snapshot, exact relation helper, and offline renderers | Keep R16 as the report owner. R17 returns a deterministic analysis model that a read-only CLI/report adapter may render; it must not replace R16’s campaign report model. |

## Persistence audit and lineage limits

R2 observations are project-scoped and read by exact `project_id` plus `subject_identity`, ordered by observation time then ID. R11.5 findings are project-scoped and require a validation ID, correlation ID, endpoint ID, parameter ID, timestamps, and non-empty safe evidence-reference IDs. R14 campaign tasks carry an optional bounded `result_reference`, but neither R14 nor R10.5 stores a universal foreign key from an R2 observation or R11.5 finding to a task.

Consequently, R17 may establish only exact, recorded relationships. It must emit deterministic gap codes—such as `OBSERVATION_MISSING`, `VALIDATION_LINEAGE_MISSING`, `CAMPAIGN_LINEAGE_MISSING`, `TASK_OUTCOME_MISSING`, `PROJECT_MISMATCH`, and `CONTRADICTORY_TIMELINE`—when an available record cannot prove the required relationship. It must never infer task lineage from a URL, task name, temporal proximity alone, or a graph edge.

## Proposed bounded R17 model

`internal/evidencecorrelation` will be a pure deterministic package with explicit, secret-screened input records. It will construct an `EvidenceChain` with typed `EvidenceLink` values, a verification state, freshness state driven by an injected bounded policy and clock, reproducibility classification derived from existing validation information, explicit gaps/contradictions, and a SHA-256 fingerprint over normalized analysis content.

The model will only accept one project. Every link will carry exact source/target type and identifier. Cross-project, blank, oversized, secret-like, or unsupported references will fail closed or become an explicit gap according to whether the selected finding itself remains valid. Inputs will be stable-sorted and duplicate links logically deduplicated. Freshness will use explicit supplied thresholds and timestamps, never wall-clock heuristics hidden in the model.

## Rejected duplication and prohibited work

R17 rejects a second HTTP client, resolver, dialer, crawler, fuzzer, injection runner, validator, risk formula, finding engine, campaign worker, scheduler, database for derived truth, graph-membership reconstruction, credentials store, and report service. It also rejects a direct correlation-to-execution loop. A future operator action remains outside R17 and requires the existing R1/R3/R10.5/R13/R14/R15 owners.

## Initial acceptance criteria

R17 is acceptable only if it provides project-isolated exact-ID evidence chains; deterministic verification, reproducibility, freshness, contradiction, and gap classifications; stable fingerprints; explicit missing lineage; no secret-like identifiers in output; no R11.5/R14/R16 mutation; and a read-only local CLI/report surface. It requires red/green unit tests, temporary-SQLite isolation coverage, contradictory/stale/missing/repeated evidence cases, fuzzing, benchmarks, race checks, prohibited-egress audit, full repository gates, updated architecture/security documentation, commit, and remote push. Main remains untouched and R18 is not started.
