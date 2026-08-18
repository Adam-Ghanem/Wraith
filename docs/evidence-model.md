# R2 Web Evidence and Asset Model

**Status:** Implemented on `feature/r2-web-evidence`; not merged into `main` by this document. R2 adds local, project-scoped canonical identities and append-only evidence persistence. It does **not** add an HTTP client, crawler, scanner, fuzzer, API, dashboard, or finding engine.

## Scope and data boundary

R2 is a data-model slice. `internal/evidence` turns already-known web metadata into canonical assets, endpoints, parameters, and typed observations. It makes no DNS query, network request, subprocess invocation, scope decision, or scanner change. A later R3 HTTP engine must use R1 `PolicyEvaluator` and `OutboundTargetGateway` before creating R2 observations from real transport activity.

| Entity | Stable project-local identity | Purpose |
| --- | --- | --- |
| `WebAsset` | `<kind>:<canonical URL>` | Deduplicated URL or JavaScript subject. |
| `Endpoint` | `<METHOD> <canonical endpoint URL>` | Request target identity; query values are excluded. |
| `Parameter` | `<endpoint identity>\|<location>\|<name>` | First-class parameter identity without parameter values. |
| `Observation` | SHA-256 over project, kind, subject, source, observed time, and normalized payload | Immutable evidence event, not a finding or exploit claim. |

Every persistence read requires a `ProjectID`, and SQLite queries always filter by it. A subject from `project-a` cannot be used to construct evidence for `project-b`; the constructors return `ErrProjectMismatch`.

## Canonical URL identity

`CanonicalizeURL` accepts only explicit HTTP(S) URLs. It lowercases ASCII hostnames, removes a trailing DNS root label, canonicalizes IPv4-mapped IPv6 addresses, removes HTTP/HTTPS default ports, normalizes a missing path to `/`, removes fragments, and sorts query keys and values. An endpoint identity intentionally omits the query string so parameters can be tracked separately.

The normalizer rejects whitespace/control characters, userinfo, non-HTTP(S) schemes, malformed or empty ports, encoded host ambiguity, non-ASCII Unicode hostnames, literal or escaped dot traversal, escaped path separators, and malformed query forms. R2 does not perform IDNA conversion: callers must supply already-ASCII/punycode hostnames to avoid silently changing target identity.

## Typed observations and secret minimization

R2 represents HTTP metadata, technology evidence, JavaScript asset evidence, and API endpoint evidence as typed observations. Payloads contain only bounded metadata. No request body, response body, cookie value, authorization credential, API key, or source-secret candidate is accepted as a first-class R2 field.

Sensitive response-header names (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, and `x-auth-token`) are stored as `REDACTED`; the resulting observation is marked `Redacted`. Existing Phase 3 potential-secret redaction remains unchanged. R2 does not convert evidence into a vulnerability finding, severity, or confidence claim.

## SQLite persistence and compatibility

Migration `005_web_evidence.sql` adds four isolated tables: `web_assets`, `web_endpoints`, `endpoint_parameters`, and `evidence_observations`. The existing scan-ledger tables and scan/history CLI output are not changed. `web_assets`, endpoints, and parameters are idempotent upserts by their project-local identities. Evidence observations are append-only: a duplicate deterministic observation ID is rejected rather than overwritten.

R2 contains a tested migration path from the repository’s simulated version-2 database through all current migrations. It intentionally does not automatically import legacy scans because Phase 1–6 scans lack an explicit R1 project ID and scope-version association. A future, explicit import command must require an operator-supplied project/scope mapping rather than guessing or widening ownership.

## Test and performance evidence

Unit and SQLite restart tests cover canonical URL identity, endpoint/parameter identity, header redaction, typed-evidence validation, project isolation, append-only persistence, and legacy scan-history preservation. Bounded fuzz targets exercise URL canonicalization and asset construction without a panic.

The following local Linux/amd64 Go 1.23.12 measurements cover URL normalization only, not database I/O, DNS, or network transport. They are characterization data, not a service-level promise.

| Query pairs | Time/op | Heap bytes/op | Allocations/op |
| ---: | ---: | ---: | ---: |
| 1 | 1,531 ns | 344 B | 10 |
| 10 | 7,068 ns | 2,567 B | 33 |
| 100 | 72,306 ns | 29,411 B | 226 |

## Deferred to R3 and later

R2 does not authorize, resolve, connect, redirect, crawl, probe, fuzz, scan, or discover any target. It does not wire existing Phase 1–6 collection paths into the new repository. R3 should introduce the shared HTTP/egress engine that performs R1 policy evaluation, DNS destination validation, redirect reauthorization, bounded transport, and typed R2 observation creation. Existing collectors must not be migrated until those transport controls are approved and tested.
