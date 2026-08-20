# R19 Architecture Audit — Continuous Security Assessment Control Plane

## Verified starting state

R19 begins on `feature/r19-continuous-assessment-control-plane` from the verified R18 commit `74498eecc1d58106fd0383b51d42836af36bea3f`. The local `main` reference remains `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`; R19 must not merge to or otherwise modify `main`.

R19 is a **local, deterministic, project-scoped control plane**. It consumes persisted R18 assessment snapshots and comparisons to evaluate explicit policy. It is not an assessment runner, scheduler, network service, scanner, or substitute for any existing lifecycle owner.

> An R19 policy failure reports recorded evidence, comparison, and threshold state. It is not proof of exploitability, remediation, authorization, or current vulnerability status.

## Verified reusable owners

| Concern | Existing authoritative owner | R19 consumption rule |
| --- | --- | --- |
| Authorization, transport, budgets, and active execution | R1, R3, R10.5, R13.2, R14, and R15 | R19 stays offline. It creates no HTTP client, DNS resolver, dialer, socket, subprocess, scheduler, or execution path. A future action executor must be separately scoped and delegate through these owners. |
| Immutable assessment state and change semantics | R18 `internal/regression` | Reuse validated `Snapshot`, `Comparison`, categories, impacts, confidence, fingerprints, unknown-coverage semantics, and cross-project rejection. R19 must not reimplement comparison or recalculate R18 changes. |
| Snapshot and comparison persistence | R18 storage records and `017_r18_regression_intelligence.sql` | Load only project-scoped snapshot and comparison rows. A selected baseline and current snapshot must be exact persisted references; no arbitrary copied snapshot content or inferred historical membership is permitted. |
| Finding and risk authority | R11.5 `SecurityFindingRecord` | R19 evaluates existing R18/R11.5 state only. It cannot rescore, create, suppress, resolve, reopen, or otherwise mutate findings or risk. |
| Evidence verification semantics | R17 correlation snapshots and `internal/evidencecorrelation` | Reuse recorded verification, freshness, reproducibility, gaps, and contradictions. Missing evidence stays missing; R19 must not infer verification from presence alone or mutate R17 snapshots. |
| Surface and campaign lineage | R11.6 snapshots and R14 campaign/cycle/task state | Reuse existing snapshot, campaign, cycle, and task references only when stored. R19 may recommend a task but must not create a campaign, cycle, task, checkpoint, or lifecycle event. |
| Reporting and offline output safety | R16 `internal/reportmodel`, `internal/reporting`, and `wraith report` | R19 supplies a normalized, secret-screened projection. R16 remains the sole owner of terminal, JSON, Markdown, and escaped self-contained HTML rendering. |

## New bounded R19 components

R19 introduces the pure `internal/continuousassessment` package because no existing owner evaluates user-defined assessment policy against an R18 comparison. The package is deterministic and has no I/O dependencies. It defines and validates the following serializable, fingerprinted models:

| Model | Purpose | Persistence rule |
| --- | --- | --- |
| `AssessmentPolicy` and `PolicyRule` | Explicit project policy, version, supported rule type/operator, threshold, and optional bounded scope. | Persist policy metadata and normalized rule JSON only after validation. |
| `AssessmentBaseline` | Immutable reference to one existing R18 snapshot and policy fingerprint. | Persist references, fingerprint, and bounded serialized metadata; never duplicate the R18 snapshot payload. |
| `ControlEvaluation` and `ControlDecision` | Rule-by-rule policy result for one baseline/current snapshot pair and R18 comparison. | Persist normalized result/action JSON idempotently by deterministic evaluation fingerprint. |
| `AssessmentAction` | Non-executing recommendation from a failed or warning control. | Persist bounded safe references only; it cannot dispatch or mutate campaign state. |
| `AssessmentSummary` | Read-only aggregate for R16 report and CLI output. | In-memory report projection only. |

Policy files will use **bounded UTF-8 JSON** rather than introducing a YAML parser or dependency. JSON is already the repository’s established machine-readable local format. Malformed, unknown-field, oversized, duplicate-rule, secret-like, unsupported-version, invalid-enum, or unsupported-operator input must fail closed.

## Evaluation and persistence contract

The first R19 policy surface will cover the R18-backed rule families named in the R19 scope: finding count/severity, new/resolved finding, regression, attack-surface growth/reduction, evidence freshness/verification/contradiction, coverage, reproducibility, missing lineage, risk band/score delta, task failure, and assessment completion. Each rule has a stable ID, policy version, enumerated operator, typed threshold, optional bounded scope, and deterministic status of `pass`, `fail`, `warning`, `informational`, `skipped`, `unsupported`, or `unknown`.

Unknown evidence, coverage, lineage, or unsupported inputs must never become `pass`. A policy can require unknown state to fail; otherwise it remains explicit `unknown` or `skipped` with a limitation. Contradictions fail only when the policy explicitly requires it. R19 will generate a stable evaluation fingerprint over the project, baseline snapshot, current snapshot, R18 comparison, normalized policy, ordered decisions, and actions.

The schema version is now `18`; migration `018_r19_continuous_assessment.sql` adds project-scoped policy, baseline, evaluation, and recommendation records with idempotent unique keys and indexes supporting project, policy, baseline, snapshot, campaign, status, and creation-time reads. Decisions remain normalized inside the bounded evaluation JSON rather than being duplicated in a second owner table. Persistence contains only normalized metadata, fingerprints, and bounded JSON—not credentials, cookies, tokens, authorization values, raw request/response data, payloads, or unredacted evidence.

## CLI, CI, and reporting boundary

`wraith assess` will remain a narrow local adapter around pure policy evaluation and project-scoped storage. Planned subcommands are policy validation/application/listing, baseline creation/showing, evaluation, CI check, and recommendation listing. Commands that merely read or persist local policy/control-plane records remain offline and do not require R1 authorization. They cannot trigger active assessment. If a later separately approved command can execute an action, it must require explicit authorization and use the existing R1/R3/R10.5/R13.2/R14/R15 path.

CI `check` distinguishes a policy failure through `ErrAssessmentPolicyFailed` from invalid input/state and internal failures. It is read-only and machine-readable; the process entry point maps success, policy failure, invalid input, and internal failure to exit codes `0`, `1`, `2`, and `3` respectively.

R16 report integration will add a report-safe assessment-control projection. Executive output will aggregate policy status, critical failures, regression/risk/surface/evidence/coverage movement, recommended-action counts, and limitations without exposing subjects. Technical output will include policy, baseline/current snapshot, R18 comparison, decision, safe lineage, and action provenance. All HTML remains escaped, self-contained, deterministic, and offline.

## Deliberate exclusions

R19 rejects a second scanner, crawler, HTTP stack, resolver, socket, subprocess, fuzzer, validator, finding/risk engine, evidence model, attack-surface graph, campaign scheduler, worker, remote API, cloud service, dashboard backend, authentication flow, credential store, or report renderer. It will not execute recommendations; expand scope; re-run validation; modify R11.5 findings/risk; modify R14 campaign state; modify R17 evidence snapshots; modify R18 snapshots/comparisons; treat missing data as safe; or reconstruct absent historical membership.

## Acceptance criteria before release

R19 is acceptable only if policy, baseline, evaluation, decision, and action behavior is deterministic, bounded, secret-screened, project-isolated, fingerprinted, and idempotent; persisted R18 references are validated exactly; cross-project and forged references fail closed; recommendations remain non-executing; R16 is reused for all rendering; no prohibited egress primitives are introduced; and red/green unit, SQLite, CLI, fuzz, benchmark, report-escaping, egress, security-review, race, full-quality, documentation, commit, and push gates pass. R19 must stop after its own feature branch is pushed and must not merge `main` or start R20.

## Implementation reconciliation

The completed implementation provides `wraith assess policy validate|apply|list`, `baseline create|show`, `evaluate`, `check`, and `actions`. Policy parsing uses a size-bounded strict JSON decoder with unknown-field rejection; policy, baseline, evaluation, decision, and action fingerprints are verified before use; project-scoped SQLite persistence is idempotent; and action identity includes the source decision fingerprint so different evaluations cannot collide. `evaluate` and `check` render through the existing R16 report model/renderer, while `wraith report` selects only the latest persisted R19 evaluation whose current R18 snapshot belongs to the selected campaign. Executive output is aggregate-only and technical output carries safe policy/baseline/current/decision/action lineage. No recommendation dispatch path exists.
