# Wraith CLI-First Web Pentesting Toolkit Roadmap

**Status:** CLI-first incremental roadmap. R1 Policy Core, R2 Web Evidence, and R3 Unified HTTP Engine are implemented on separate feature branches and remain unmerged at the time of this update. The roadmap deliberately prevents a bounded local tool from becoming an unsafe scanner fleet or an unnecessary SaaS platform through a single rewrite.

## Product direction

Wraith evolves toward an authorization-first, modular Web and API pentesting toolkit. The durable product value is not maximum scanning breadth; it is **bounded collection, explicit scope, explainable evidence, reliable history, scriptable output, and operator-controlled decisions**.

Every future stage must preserve these non-negotiable rules:

1. Authorization is explicit, current, recorded, and scoped; technical reachability is never authorization.
2. Deny rules override allow rules; DNS, redirects, discovered links, scripts, and tool output cannot expand scope.
3. Every active operation has a timeout, cancellation path, concurrency/rate/request budget, and partial-result state.
4. Raw observations, inferred correlations, recommendations, and operator decisions are separate data types.
5. Credentials are never guessed, replayed, validated, logged, or exfiltrated by Wraith.
6. Exploitation, persistence, destructive activity, and autonomous offensive actions remain excluded.
7. A new protocol, target class, scheduler, external provider, remote API, plugin, or data sink requires a design review and threat-model update before implementation.

## Delivery sequence

| Stage | Outcome | Adds active network behavior? | Exit criteria |
| --- | --- | ---: | --- |
| R0 — Audit baseline | Architecture, technical debt, roadmap, and platform threat model. | No | The present documents are reviewed and accepted. |
| R1 — Policy core | Versioned project scope, allow/deny rules, authorization records, and deterministic target evaluator. | No | **Implemented on feature branch:** domain/CIDR/URL/port matching, normalized targets, expiry, revocation, project isolation, deny precedence, redirect/post-resolution design tests, fuzzing, and SQLite persistence. Existing scanners remain unchanged. |
| R2 — Web evidence / asset model | Canonical web asset identity, endpoints, parameters, typed observations, provenance, and migration/import plan. | No | **Implemented on feature branch:** project-isolated canonical URL/JavaScript assets, endpoint and parameter identities, append-only typed HTTP/technology/JS/API observations, sensitive-header redaction, SQLite persistence, migration compatibility tests, fuzzing, and benchmarks. No risk or vulnerability claim is fabricated. |
| R3 — Unified HTTP engine | Central outbound HTTP transport, R1 enforcement, DNS destination validation, redirect reauthorization, budgets, and source interface. | Not beyond existing paths | **Implemented on feature branch:** Phase 2–3 target-web paths use one project-scoped engine with pinned resolution, destination checks, redacted R2 observations, reusable connections, local rate/concurrency bounds, safe retries, and explicit proxy controls. |
| R4 — Web crawler | Bounded, same-policy link/form/script/redirect/sitemap collection. | Approved bounded HTTP only | **Implemented on feature branch:** a project-scoped R3-backed canonical crawler and CLI command with canonical deduplication, bounded crawl budgets, robots/sitemap/security.txt discovery, and local security verification. R5 remains unstarted. |
| R5 — Endpoint discovery | Method, path, and parameter extraction from existing evidence/crawl results. | No new protocol | **Implemented on feature branch:** deterministic project-scoped endpoint/parameter/form/API/GraphQL/OpenAPI inventory over R2 records plus bounded local JSON spec parsing. R6 remains unstarted. |
| R6 — JS and API intelligence | JavaScript, OpenAPI, and safe GraphQL evidence analysis. | No new protocol | **Implemented on feature branch:** parser-backed static local JavaScript and local source-map analysis, deterministic client-side metadata, R2/R5 endpoint correlation, project isolation, and zero analysis-time network I/O. R7 is separately scoped. |
| R7 — Controlled fuzzing | Explicit endpoint/parameter generic mutation, baselines, response intelligence, and redacted observations. | Approved bounded HTTP only | **Implemented on feature branch:** deterministic bounded profiles, safe-method default, explicit unsafe-method confirmation, R1/R3-only execution, cancellation-aware local jobs, response fingerprints, reflection/error metadata, project isolation, dry-run, and R2 fuzz observations. No finding system or credential testing is included. |
| R7.5 — Content discovery | Explicit local wordlist path/file and virtual-host discovery with soft-404 filtering. | Approved bounded HTTP only | **Implemented on feature branch:** project-local base evidence, local-only bounded wordlists, R1/R3-only baseline/candidate execution, candidate-host R1 authorization, content fingerprints, redacted R2 evidence, depth-capped non-crawling recursion, and `content`/`vhost` CLIs. No findings or R8 validation. |
| R8 — Security validation engine | Safe, evidence-led validation checks only. | Approved bounded HTTP only | **Implemented on feature branch:** explicit project endpoint selection, one-request `validate` CLI with dry-run, R1/R3-only refresh, deterministic passive security-header/CORS/cookie/error/banner checks, reproducibility keys, lifecycle-ready observed results, redacted R2 validation observations, SQLite migration compatibility, fuzzing, benchmarks, and quality verification. No destructive exploitation, credential abuse, payloads, or automatic confirmation. |
| R9 — Vulnerability intelligence | SQLite-compatible asset graph, deduplication, correlation, confidence, and change detection. | No new protocol by default | **Implemented on feature branch:** deterministic project-scoped asset/endpoint graph, same-origin typed edges, evidence-only candidate correlation, explainable bounded confidence, new/changed/unchanged/removed detection, local `intelligence` CLI, and SQLite graph/correlation schema. No graph service, remote advisory source, network I/O, severity invention, or exploitation claim. |
| R10 — Authenticated security | Implemented on feature branch | Bounded HTTP | Explicit dual gate, project-scoped identities, bounded sources, secret-free persistence, and protection stops. |
| R10.5 — Full-spectrum pentest orchestrator | Implemented on feature branch | Reuses approved bounded behavior only | Deterministic plans and phase graph; one global request/rate/concurrency budget; project-scoped run/phase/event history; fail-closed resume of incomplete safe phases; local terminal/JSON/Markdown/HTML reports. It adds no alternate transport, target class, scheduler, secret persistence, or automatic authentication attack. |
| R11.1 — Request mutation engine | Implemented on feature branch | No | Deterministic, bounded, project-scoped baseline and query/path/form/JSON/safe-header variants over existing R2 identities, with secret-safe fingerprints. It has no execution path. |
| R11.2 — Smart content and parameter discovery | Implemented on feature branch | Explicit `--verify` only | Deterministic R5/R2/R6-derived candidates, provenance merging, safe local wordlists, and non-vulnerability discovery priorities. Passive mode has no network; explicit verification uses `HEAD` through R3 with R10.5 global budgets and redacted R2 evidence. |
| R11.3 — Injection testing engine | Implemented on feature branch | Explicit library execution seam; CLI plan/dry-run only | Project-scoped canary tests reuse R11.1 composition, R7 analysis, R3 dispatch, R10.5 controls, and redacted R2 signals. Only `GET`/`HEAD` are allowed; `429` stops execution; R8 handoff is explicit. |
| R11.4 — Finding validation and evidence correlation | Implemented on feature branch | Explicit library execution seam; CLI plan/dry-run only | One R11.3 signal is reproduced with fixed baseline/mutation pairs under an injected R1 recheck, R3, and R10.5 controls. R8 writes redacted R2 evidence, deterministic repeatability produces a temporary finding candidate, and R9 receives only validated evidence-backed candidates. No final finding model, scheduler, or transport is added. |
| R11.5 — Security findings and risk intelligence | Implemented on feature branch | Local library/storage/CLI only | Validated R11.4/R9 candidates become deterministic project-scoped findings with versioned explainable scores, explicit lifecycle/history/suppression controls, and stable `findings`/`risk` local output. It introduces no network, scanner, validation, correlation, or exploitation behavior. R11.6 remains unstarted. |
| R12 — Reporting | Local JSON/JSONL/CSV/Markdown/HTML reporting. | No | Redaction and evidence provenance are retained. |
| R13 — Lightweight extensions | Narrow, reviewed extension interfaces. | Subsystem-specific | Extensions inherit policy, budgets, and evidence controls. |
| R14 — Performance and hardening | Bounded concurrency, reusable connections, streaming output, benchmarks, and security review. | No new capability by default | Safety and correctness are not traded for throughput. |

## First approved implementation slice: R1

The next code change after audit was **R1 — Policy core**, not a REST API, crawler, scheduler, PostgreSQL migration, worker queue, or generic plugin system. R1 remains intentionally non-scanning. It introduced:

| Deliverable | Required behavior |
| --- | --- |
| Project scope document | Immutable scope version with owner, authorization reference, expiry, and approved activity classes. |
| Scope rule grammar | Domain/subdomain, IPv4/IPv6 CIDR, URL, and port rules with explicit allow/deny semantics. |
| Deterministic evaluator | Deny wins; returns a machine-readable decision and reason without making network requests. |
| Target normalization | Canonicalizes user input without using output to infer new scope. |
| Test corpus | Wildcards, suffix confusion, punycode/normalization, IPv4/IPv6, CIDR boundaries, port cases, URL parsing, redirects, DNS-rebinding fixtures, and expired/revoked authorization records. |
| Compatibility boundary | Existing Phase 1–4 commands preserve their documented behavior until a reviewed migration adopts the new policy core. |

R1 did not mark the egress boundary complete: transport-level DNS validation, resolution pinning, private/reserved-address policy, redirect handling, request budgets, and migration of target-web collectors became **R3** work. R3 now completes that boundary for probe, content discovery, and JavaScript analysis; provider APIs and optional subprocesses remain deliberate exceptions requiring their own scoped adapters.

## Deferred module plans

### Asset and observation intelligence

R2 introduces stable project-local URL/JavaScript asset identities, endpoint/parameter identities, and typed append-only observations in SQLite. An asset is not a scan result: it is a deduplicated subject. Observations record what a source saw, when, and under which source; they do not claim a finding. Existing scan rows remain preserved as legacy evidence, but are not automatically imported because they lack a safe project/scope association. Broader identities—domains, IPs, ports, services, certificates, technologies, cloud assets, repositories, containers, and applications—remain future slices.

### API and dashboard

The static dashboard remains a useful offline evidence viewer. An authenticated API/dashboard begins only in R6 after project ownership, object authorization, retention, and audit contracts exist. It must use live backend data only after those contracts; no fabricated dashboards, invented risk scores, or placeholder security status are acceptable.

### Monitoring and workers

R7 is a deployment and governance feature, not a CLI loop. A scheduled scan must bind an immutable scope/authorization snapshot, revalidate expiry before execution, retain cancellation and budget controls, record requester/approval context, and stop rather than automatically broaden scope. An always-on service, queue, or worker fleet should be selected only after workload, runtime, cost, ownership, and incident-response requirements are explicit.

### Risk, graph, and AI

Risk scoring, attack graphs, and AI analysis come after observations and findings have stable identity, provenance, confidence, and lifecycle. A future UI must label **Observed evidence**, **Inference**, **Recommendation**, and **Operator decision** separately. AI may summarize or explain a reviewed evidence set, but it must not execute active operations, widen scope, override a denial, or turn a low-confidence correlation into a confirmed vulnerability.

## Deployment decision gates

| Need | Lighter path | Higher-complexity path | Decision required before implementation |
| --- | --- | --- | --- |
| Local single-user evidence | Embedded SQLite and CLI/static dashboard. | Authenticated local service. | Data retention, users, and live-access requirement. |
| Occasional approved runs | Operator-initiated CLI. | Scheduled jobs. | Authorization expiry, approval workflow, cancellation, and run ownership. |
| Larger data/query load | Indexed SQLite with measured limits. | PostgreSQL. | Measured workload, migration, backup/restore, and operations owner. |
| External tools/providers | Explicit local adapter with fixtures. | Plugin/worker ecosystem. | Permission declaration, sandboxing, rate/terms review, audit, and failure isolation. |
| Live event UI | Refresh from local evidence. | API/event gateway. | Authentication, tenant isolation, event authorization, and durable state. |

## Excluded until explicitly re-approved

Wraith will not add automatic exploitation, credential testing, password spraying, persistence, malware delivery, destructive tests, arbitrary target injection, external data exfiltration, autonomous AI actions, internet-wide scanning, or automatic scope expansion. “Full” profiles must not become an escape hatch around the authorization and budget controls.

## Governance checkpoints

Before each stage, the maintainer must approve a one-page scope decision, updated responsible-use language, threat model, interface/data contract, test plan, migration/rollback plan where applicable, and release criteria. A stage is complete only when its tests and documentation prove its boundary—not when a demo reaches a target.
