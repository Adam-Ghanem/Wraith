# R22 Security Review — Continuous Assessment Intelligence & Decision Engine

## Scope and security boundary

R22 is a deterministic, offline interpretation layer over validated, project-scoped R18–R21 records. It produces immutable decision snapshots and **non-executing** candidate metadata. It does not scan targets, make HTTP or DNS requests, create sockets, start subprocesses, schedule work, dispatch jobs, mutate owner records, or claim remediation, revalidation, or security assurance.

## Threat model and controls

| Threat | Relevant boundary | R22 control | Fail-closed result |
|---|---|---|---|
| Cross-project leakage | Persisted R18–R21 records and decision cache | Project ID is required and revalidated through source lineage before model evaluation or cache reuse. | Reject the source/snapshot; no decision candidate is produced. |
| Forged source or fingerprint | JSON source records and immutable cache | The storage adapter reconstructs canonical source state, checks fingerprints and relationships, and validates cached canonical content against fresh reconstruction. | Reject the source/cache; never trust a forged stored projection. |
| Stale or contradictory intelligence | R17 evidence, R18 comparison, R19 evaluation, R20 governance, R21 analytics | Source freshness and quality are represented as explicit constraints, and quality can block/degrade candidates. | Return blocked, degraded, or unknown decision metadata rather than a confident recommendation. |
| Secret-bearing identifiers | CLI inputs, source identifiers, report fields | Bounded identifier/fingerprint validation and secret-like screening are applied by the R22 model, storage boundary, and report projection. | Reject unsafe source/report fields. |
| Report injection | Markdown and HTML report outputs | The report model performs secret screening; Markdown normalizes control characters and HTML output escapes all values. | Unsafe output is rejected or encoded, never rendered as active markup. |
| Recommendation-as-execution confusion | CLI, storage, report, and user interpretation | Every candidate carries `non_executing=true`; projection validation rejects `false`; user-facing summaries say recommendations do not schedule, dispatch, remediate, or revalidate. | A candidate cannot be represented as an execution record. |
| Unauthorized operator use | Decision CLI | All R22 decision commands require the established `--authorized` acknowledgement gate. | Refuse command execution before database access or output persistence. |
| Output-path traversal | Decision export CLI | Existing safe local output path validation is used before export. | Refuse unsafe destination paths. |

## Code-path review

The reviewed R22 package (`internal/decisionintelligence`) is pure and has no I/O imports. The storage adapter (`internal/storage/decision.go`) only reads/revalidates established local records and writes immutable, idempotent R22 snapshots. The CLI (`internal/cli/decision.go`) uses the existing local database and output helpers; it adds no network client, DNS resolver, socket, subprocess, scheduler, worker, scanner, or external service integration.

The R16 report integration rebuilds a R22 projection from verified sources. If a legacy or incomplete R16 history cannot satisfy the strict R22 source contract, the report displays an **unavailable** decision projection with an explicit limitation; it does not manufacture a decision from incomplete data.

## Residual limitations

R22 is not a security finding engine, vulnerability scanner, remediation service, or assurance mechanism. Its quality and confidence are bounded by the validity, scope, freshness, and completeness of pre-existing R18–R21 artifacts. A decision candidate is descriptive evidence for human review, not a command or proof of outcome.

## Verification evidence

The R22 tests cover deterministic output, source contradiction blocking, cross-project rejection, forged-priority rejection, freshness decisions, required non-executing metadata, cache validation, project isolation, restart safety, authorized-use gating, and unsafe output-path rejection. The release suite additionally checks formatting, race behavior, static analysis, buildability, web checks/audit, and whitespace integrity.
