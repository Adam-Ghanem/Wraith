# R16 Audit — Assessment Result Intelligence and Reporting

## Scope and branch boundary

R16 begins on `feature/r16-assessment-reporting` from the completed R15 commit `f0aff58e50ba0e5285d2e7715dfbcd76d0f3cfc3`. The `main` branch remains at `42cb8b285f98d6f36ad3f8f863497d11db8e11f2`. R16 is a read-only local analysis and reporting slice; it must not merge to `main` or begin R17.

> R16 may assemble and render authoritative local data, but it must not scan, crawl, execute tasks, mutate lifecycle state, create findings, recalculate risk, add egress, or introduce an external reporting service.

## Verified ownership and reusable seams

| Domain | Authoritative owner | R16 consumption rule |
| --- | --- | --- |
| Project scope and authorization | R1 `policy` | Surface stored scope metadata only; do not re-evaluate, broaden, or treat a report as authorization. |
| Web assets, endpoints, parameters, and observations | R2 `evidence` / project-scoped SQLite | Reference canonical project-local identities and redacted observation metadata; never copy raw request/response values. |
| Active transport and controls | R3 / R10.5 | R16 creates no HTTP client, resolver, socket, subprocess, budget, rate limiter, or concurrency controller. |
| Validation | R8 and R11.4 | Report only existing observed/validated state and evidence references; a signal or response differential is not a finding. |
| Correlation | R9 | Preserve existing correlation identities and evidence-backed relationships; do not deduplicate or infer root causes. |
| Findings and risk | R11.5 `riskintelligence` / SQLite | Reuse stored finding lifecycle, severity, risk score/band/version, remediation hint, and safe evidence references; never create a second finding or risk model. |
| Attack surface | R11.6 `attacksurface` / SQLite | Consume immutable project-scoped snapshots, nodes, edges, coverage, and visibility gaps; do not mix snapshots or claim graph paths are exploitable. |
| Assessment and lifecycle | R13/R13.2 through R10.5 persistence | Reuse deterministic plans, task results, secret-free run/phase/event records, and dry-run semantics. |
| Campaign state | R14 `campaign` / SQLite | Reuse campaign, cycle, task, checkpoint, and event records with their existing status vocabulary and secret-free references. |
| Built-in active owners | R15 `assessmentbuiltin` | Report truthful completed, partial, blocked, failed, cancelled, and typed-unavailable outcomes without implying complete assessment coverage. |

## Existing reporting capability

`internal/pentest/report.go` provided the initial offline-format precedent. R16 now adds `internal/reportmodel`, `internal/correlation`, `internal/reporting`, project-scoped campaign read accessors, and `wraith report`. The command loads one selected campaign, its authoritative R11.5 findings, and latest stored R14 task outcomes; normalizes a secret-screened in-memory snapshot with a stable SHA-256 content fingerprint; and renders `terminal`, `json`, `markdown`, or escaped self-contained `html` locally.

## Security boundary findings

| Threat | Required R16 control |
| --- | --- |
| Cross-project leakage | Every read and every relationship must carry the selected project ID. Mismatched source records must fail closed or be excluded with a stated limitation. |
| Secret disclosure | Use allowlisted identifiers, classifications, counts, timestamps, redacted metadata, evidence references, and existing remediation hints only. Exclude credentials, cookies, authorization headers, request values, payloads, raw bodies, candidate fingerprints, and session material. |
| Overstated security claim | Distinguish planned, executed, observed, validated, finding-bearing, and unknown/uncorrelated states. Never promote discovery, a signal, an HTTP status, or a graph edge into a vulnerability. |
| Risk-model drift | Display only the R11.5 authoritative risk score, band, factors/version, and severity. R16 can aggregate or order existing values but must not rescore. |
| Snapshot inconsistency | Build a deterministic in-memory report snapshot from one selected campaign/assessment/surface context. Stable sort all collections and fingerprint normalized content without volatile timestamps. |
| Unsafe rendering | Keep JSON machine-readable, Markdown stable, terminal concise, and HTML self-contained with escaped content and no CDN, remote CSS, fonts, JavaScript, tracking, or network calls. |
| Lifecycle mutation | CLI is read-only: no network I/O, campaign writes, checkpoint updates, finding writes, risk writes, or lifecycle writes. |

## Candidate R16 architecture

The audit supports three local packages: `internal/reportmodel` for deterministic, secret-minimized snapshot and provenance contracts; `internal/correlation` for explicit project-scoped relationships derived only from stable existing IDs; and `internal/reporting` for assembly plus terminal/JSON/Markdown/HTML renderers. The CLI should remain a narrow read-only adapter that validates project/campaign/filter arguments, opens the existing SQLite database, requests one report snapshot, and writes an optional local output file.

## Known limitations to preserve

The report must state rather than hide incomplete owner coverage, unresolved campaign tasks, unavailable owners, missing source references, absent surface snapshots, and zero-denominator coverage. It must not claim a campaign is successful merely because no finding appears, and it must not count planned work as executed or observations as validated findings.

## SQLite audit and reporting-data availability

| Schema generation | Authoritative data | R16 treatment |
| --- | --- | --- |
| `001`–`003` | Legacy scan, content, JavaScript, port, and external-template rows | Keep separate from the project-scoped report model; do not promote legacy scan-era records to R11.5 validated findings. |
| `004` | Immutable scope versions, rules, and active-scope pointers | Report selected stored scope metadata and rules only when attached to the selected campaign; never use a report request to alter scope. |
| `005`–`009` | R2 assets, endpoints, parameters, and redacted typed observations | These are provenance roots. The storage API reads them project-scopingly and deterministically; observations are currently queried by project plus subject identity. |
| `010` | R9 correlation graph and correlation records | Preserve existing correlation identifiers; do not rebuild R9 relationships into a second correlation authority. |
| `011` | R10 identity/session/authentication metadata and protection-stop observations | Report only availability, status, and bounded categories/counts. Never render credential identifiers as credentials, tokens, cookies, headers, or values. |
| `012` | R10.5 `pentest_runs`, phase records, and append-only events | Use recorded status/phase/event lifecycle; R13.2 maps assessment results into these tables. |
| `013` | R11.5 security findings, risk assessments, history, and suppressions | This is the authoritative finding/risk source. `ListSecurityFindings` is project-filtered, uses the existing severity/status/class/minimum-risk/asset filters, and stable-sorts by risk, severity, then finding ID. |
| `014` | R11.6 surface nodes, edges, and snapshot metadata | Campaigns carry an immutable snapshot reference. Storage currently exposes project-wide nodes/edges rather than a snapshot-membership ledger, so R16 must report the selected snapshot metadata/counts and explicitly label detailed surface membership as unavailable unless the source can prove it belongs to that snapshot. |
| `015` | R14 campaigns, cycles, tasks, checkpoints, and events | Campaign records are project-scoped, secret-screened, and checkpointed. R16 adds read-only, parameterized, deterministic list accessors for cycles, tasks, and events rather than a parallel schema. |

`internal/pentest/report.go` confirms existing rendering conventions: deterministic ordering, machine-readable JSON, stable Markdown, escaped offline HTML, and no remote assets. `internal/cli/findings.go` confirms that risk output is an aggregation over stored R11.5 records, not a second risk engine. `internal/cli/surface.go` presently rebuilds a graph from live mixed source records; R16 must not present that as the membership of a stored campaign snapshot.

## Implemented correlation and coverage rules

| Relationship | Matching key | Output and failure behavior |
| --- | --- | --- |
| Finding identity | Exact selected-project R11.5 record ID | `--finding` filters after the authoritative project-scoped storage query; unknown IDs yield an empty findings array rather than a cross-project fallback. |
| Finding set | Existing R11.5 project/severity query | R16 preserves R11.5 storage ordering and displays only stored IDs, severity, and score; it does not rescore or create findings. |
| Campaign task coverage | Latest stored R14 status for each assessment task ID, ordered by deterministic cycle reads | `completed` contributes to the numerator; all latest recorded task outcomes contribute to the denominator. No task rows produce `N/A`, and blocked/failed/skipped/unavailable work is explicitly incomplete. |
| Generic local relation helper | Matching project ID plus exact endpoint/observation identity | `internal/correlation` returns an explicit uncorrelated result for project mismatch or missing stable references; it does not use URL-prefix or fuzzy association. |
| Surface snapshot membership | R14 snapshot reference plus R11.6 metadata only | Detailed membership is intentionally omitted until a membership ledger exists; R16 does not reconstruct current graph rows as historical campaign membership. |

## Acceptance criteria

R16 is complete only if it provides a deterministic normalized report snapshot with a stable content fingerprint; project-scoped reads; exact-ID provenance; explicit unknown/uncorrelated limitations; read-only terminal, JSON, Markdown, and escaped self-contained offline HTML output; CLI filter validation; zero network I/O and zero lifecycle/data mutation; cross-project rejection; deterministic ordering; secret redaction; zero-denominator `N/A` coverage; and focused unit, SQLite, CLI, fuzz, benchmark, race, egress, and full quality coverage. The branch verifies those properties through red/green unit and CLI regressions, project-isolated temporary SQLite accessors, a 2-second snapshot fuzz run, a snapshot benchmark, focused race tests, a prohibited-egress source audit, full Go/race/vet/build gates, frontend checks/tests, production dependency audit, and whitespace validation. No R17 work, `main` merge, scheduler, report service, risk scorer, finding creator, active execution, or new egress primitive is permitted.

## Audit conclusion

The verified implementation uses the existing SQLite repository directly through narrow project-scoped methods, a deterministic report model, an exact-ID correlation helper, and renderers modelled after the established offline pentest renderer. It needs no persistence migration: report snapshots are deterministic in-memory views, not a new durable source of truth. The remaining boundary is intentional: R16 does not fabricate R11.6 snapshot membership, report unrecorded evidence as provenance, or represent partial campaign outcomes as full coverage.
