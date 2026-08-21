# T7 Baseline Audit: Data Classification and Evidence Protection

## Purpose and Method

This audit records the repository state at the T7 base commit `b82a71c6dec19f48273ff5bd1c42b782f7177bfd`. It is source-authoritative: the classified seams were identified from production Go call sites, constructors, storage repositories, renderers, CLI dispatch, migrations, and inherited T1–T6 contracts. T7 is a local representation, persistence, and output-governance layer. It does not own target authorization, scope, trust, network dispatch, DNS, transport, scanning, or credential handling.

## Existing Controls and Gaps

| Boundary | Existing control | T7 classification | T7 decision |
|---|---|---|---|
| R2 `internal/evidence` constructors | Bounded payloads; explicit `Redacted`; credential/header/body exclusions; selected sensitive header masking | Partial, duplicated marker logic | Retain R2 meanings and route governed representations through one pure T7 authority before persistence. |
| R2 `AppendObservation` | Project-scoped immutable insert; valid JSON and 32 KiB cap | Missing classification metadata and universal secret validation | Add a governed observation representation and fail-closed persistence validation. |
| R11.5 finding storage | Project-scoped rows; safe evidence-reference check | Descriptive fields, risk metadata, and JSON factors are not centrally governed | Validate representation before persistence and do not alter risk scoring. |
| R16 report model | Snapshot validates many report-facing fields using local `secretLike` logic and deterministic fingerprints | Strong upstream boundary but repeated noncanonical marker set | Replace only the local classification predicate with T7’s canonical decision; retain R16 snapshot semantics and fingerprint construction. |
| R16 renderers | Terminal, JSON, Markdown, and escaped offline HTML render one validated snapshot | Renderer assumes callers supplied safe content | Maintain the validated snapshot boundary; add T7-governed report/export validation before renderer dispatch. |
| Assessment adapter context | Excludes credential/cookie/header/payload data and rejects unsafe references | Narrow execution-specific safeguard | Retain as defense in depth; do not move trust or execution validation into T7. |
| T3 authorization audit | Append-only, project-scoped, fingerprinted, secret-minimized event rows | Correct pattern but not a data-governance event model | Reuse the persistence pattern for a separately typed T7 governance audit event. |
| T5 operation metadata | Rejects credential-bearing destinations and secret-like identifiers before policy/audit delegation | Narrow outbound-metadata safeguard | Reuse canonical T7 detection only if it does not create an authority cycle; retain T5 policy order and audit semantics. |
| `wraith report` and assessment output | Writes rendered report bytes with mode `0600` | File/terminal output has no universal export decision | Govern output by classification before write or stdout. |
| `wraith export-fixtures` | Delegates to direct `runScan`/`runHistory` and writes JSON with mode `0600` | Legacy file-export and egress bypass risk | Block active fixture export until a reviewed T5/T7-compatible safe export contract exists. |
| Web dashboard | Same-origin static fixture loading only | Local/offline presentation, not target-web egress | Retain unchanged; do not add telemetry or API paths. |
| Tests | Loopback, fake transports, fixture data | Test-only | Exclude from production allowlists; retain test coverage. |

## Canonical Sources of Authority

| Concern | Existing authority retained by T7 |
|---|---|
| Authorization lifecycle | T1 |
| Scope and target normalization | T2 |
| Trust assurance and authorization audit | T3 |
| Derived trust propagation | T4 |
| Outbound policy decision and R3 delegation precondition | T5 |
| Legacy egress adoption and CLI denial | T6 |
| HTTP/DNS/socket transport and redirect controls | R3 |
| Evidence meaning, validation meaning, finding risk semantics, and report semantics | R2, R8, R11.5, R16, and R17–R21 respectively |

## Migration Baseline

The current schema version is 24 and the latest migration is `024_t3_authorization_audit_events.sql`; T7 therefore uses additive migration number **025**. No existing evidence, finding, authorization, scope, trust, campaign, reporting, analytics, or decision records are rewritten or reinterpreted.

## Required T7 Enforcement Outcome

T7 must supply one pure, deterministic classifier/redactor for clearly secret-bearing strings, headers, query/form keys, structured bodies, and credential-bearing URLs. Every governed write, audit event, report/export projection, and CLI-facing output must fail closed on an unsafe representation or emit a redacted safe representation. The classifier must never itself perform I/O.
