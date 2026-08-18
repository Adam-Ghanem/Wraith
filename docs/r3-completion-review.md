# R3 Completion Review

**Reviewed branch:** `feature/r3-http-engine`
**Scope:** R3 only. This review does not start R4.

## Legacy collector migration matrix

| Collector | Network I/O | Previous transport | R3 decision | Completion rationale |
| --- | ---: | --- | --- | --- |
| `internal/probe` | Yes | Direct `net/http` | **Migrated** | It now requires a project ID and `httpengine.Client`; read-only metadata, same-host redirects, body bounds, and safe timeout retry remain explicit. |
| `internal/contentdiscovery` | Yes | Direct `net/http` | **Migrated** | Baseline and candidate paths now issue project-scoped R3 requests while preserving random baseline comparison, rooted paths, per-host pacing, same-host redirects, and body caps. |
| `internal/jsanalysis` | Yes | Direct `net/http` | **Migrated** | Page and same-origin script reads now use R3; file bounds, same-host redirects, safe timeout retry, and secret redaction remain in place. |
| `internal/enum` CRT/VT sources | Yes | Direct `net/http` | **Intentional exception** | These are third-party provider API calls rather than target-web collection. Their provider terms, credentials, source provenance, and policy semantics need a dedicated adapter decision. |
| `internal/discovery` / `internal/ports` | No HTTP | Local sockets | **Intentional exception** | Phase 1 has a separate selected-interface/local-CIDR boundary; R3 is not a socket-scanning migration. |
| `internal/portscan` / `internal/vulncheck` | Optional subprocess | External binaries | **Intentional exception** | Nmap/Nuclei require a separate policy-aware command-adapter design; R3 does not silently change their tool behavior. |

The `scan` command now requires `--project PROJECT` in addition to `--authorized`. It constructs one R3 engine backed by the SQLite R1 evaluator and R2 observation repository, and passes that engine only to the migrated target-web collectors. Existing provider and subprocess exceptions are documented rather than treated as transitively authorized target traffic.

## R3 definition-of-done evidence

| Requirement | Evidence |
| --- | --- |
| Central transport and R1 before I/O | `httpengine.Engine` authorizes `ActionHTTP` before rate limiting, DNS, and dialing. |
| Controlled DNS and pinning | Injected resolver, address validation, `ActionConnect`, and validated-address dial mapping. |
| Destination safety | Loopback, private, link-local, multicast, CGNAT, documentation, benchmark, and reserved ranges fail closed by default. |
| Redirect safety | Manual per-hop parsing, authorization, resolution, validation, and optional collector redirect validator. |
| Resource controls | Request timeout, cancellation, response bound, redirect bound, default local limiter, bounded concurrency, reusable pool, and idle cleanup. |
| Retry safety | Default one attempt; bounded opt-in retries for safe methods with policy/rate re-entry on every attempt. |
| Proxy safety | Explicit valid HTTP(S) proxy only, no environment proxy, generic invalid-config error, target authorization before proxy connection. |
| TLS and sensitive data | TLS 1.2 minimum with verification; R2 redaction before observation persistence. |
| Project isolation | Every engine/collector request carries a mandatory project ID consumed by R1 and R2. |
| Tests and characterization | Local fixture tests, race suite, bounded fuzz targets, and transport benchmarks. |

## Focused security review

The review considered authorization-before-I/O, DNS rebinding, redirect and proxy scope bypass, IPv4-mapped IPv6, local/private/reserved ranges, malformed URL/proxy input, unsafe retry replay, rate/concurrency bypass, connection reuse, header/cookie handling, TLS verification, redaction, project IDs, and collector behavior. The target policy is evaluated before the proxy transport may connect, and retry attempts restart the protected sequence. No test uses an external Internet target.

## Known limitations

R3 is a local CLI transport boundary, not a distributed egress gateway. The local rate/concurrency limit is process-local; proxy selection is an operator trust decision; provider APIs and optional external binaries remain separate reviewed exceptions; there is no CLI scope-authoring workflow; and crawling, fuzzing, security checks, scheduling, and R4 are intentionally out of scope.
