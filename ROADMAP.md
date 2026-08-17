# Wraith Full-Spectrum Platform Roadmap

**Status:** Proposed incremental roadmap based on the repository audit. It is deliberately staged so the project does not convert from a bounded local tool into an unsafe scanner fleet through a single rewrite.

## Product direction

Wraith can evolve toward an authorization-first attack-surface and security-evidence platform. The durable product value is not maximum scanning breadth; it is **bounded collection, explicit scope, explainable evidence, reliable history, and operator-controlled decisions**.

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
| R1 — Policy core | Versioned project scope, allow/deny rules, authorization records, and deterministic target evaluator. | No | Domain/CIDR/URL/port matching, redirects, DNS, IPv6, SSRF cases, expiry, and deny precedence have high-confidence tests. |
| R2 — Evidence model | Unified asset identity, observations, provenance, normalized findings, and migration/import plan. | No | SQLite migrations preserve existing evidence; no risk or vulnerability claim is fabricated. |
| R3 — Egress gateway | Central outbound DNS/HTTP/TLS validation, budget policy, and source/provider interface. | Not beyond existing paths | Every existing web path moves through the gateway and tests prove blocked redirects/private targets cannot bypass policy. |
| R4 — Safe intelligence expansion | Passive DNS/certificate/TLS/API-documentation/fingerprint collection through approved providers. | Only separately approved bounded collection | Each provider has terms review, data-classification, cache/rate policy, fixtures, and source-error output. |
| R5 — Finding intelligence | CPE/CVE/advisory correlation with evidence, rule version, confidence, and analyst review state. | No exploitation | No confirmed vulnerability is inferred from a version/banner alone; uncertainty is visible. |
| R6 — Authenticated local service | Authenticated API, project RBAC, audit events, pagination, live dashboard API, and SQLite local service mode. | No new scanner class | Object authorization, rate limits, secure sessions/API keys, migration, backups, and integration tests pass. |
| R7 — Controlled automation | Durable jobs, schedules, notifications, worker abstraction, and project-level approval snapshots. | Only approved jobs | Cancellation, idempotency, retry, expiry, audit, budget, and authorization revalidation are verified. |
| R8 — Production scale decision | PostgreSQL adapter, queue/worker backend, observability, deployment model, and retention operations. | No new capability by default | Load tests, backups/restores, monitoring, incident runbooks, and access reviews are complete. |
| R9 — Optional ecosystems | Plugins, cloud providers, AD inventory, reports, attack-path reasoning, and AI-assisted analysis. | Subsystem-specific | Each capability clears its own scope, threat model, provider/tool review, and security acceptance gates. |

## First approved implementation slice: R1

The next code change should be **R1 — Policy core**, not a REST API, crawler, scheduler, PostgreSQL migration, worker queue, or generic plugin system. R1 is intentionally non-scanning. It should introduce:

| Deliverable | Required behavior |
| --- | --- |
| Project scope document | Immutable scope version with owner, authorization reference, expiry, and approved activity classes. |
| Scope rule grammar | Domain/subdomain, IPv4/IPv6 CIDR, URL, and port rules with explicit allow/deny semantics. |
| Deterministic evaluator | Deny wins; returns a machine-readable decision and reason without making network requests. |
| Target normalization | Canonicalizes user input without using output to infer new scope. |
| Test corpus | Wildcards, suffix confusion, punycode/normalization, IPv4/IPv6, CIDR boundaries, port cases, URL parsing, redirects, DNS-rebinding fixtures, and expired/revoked authorization records. |
| Compatibility boundary | Existing Phase 1–4 commands preserve their documented behavior until a reviewed migration adopts the new policy core. |

## Deferred module plans

### Asset and observation intelligence

R2 should introduce stable asset identities for organization, project, domain, subdomain, IPv4/IPv6, host, URL, port, service, certificate, technology, cloud asset, repository, container, and application. An asset is not a scan result: it is a deduplicated subject. Observations record what a source saw, when, under which scope/run, and at what confidence. Existing scan rows must remain importable evidence.

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
