# R3 Unified HTTP Engine

**Status:** Complete on `feature/r3-http-engine`. `internal/httpengine` is the single project-scoped HTTP(S) egress boundary for the migrated Phase 2–3 target-web collectors and the `wraith http` command. It is deliberately a transport layer, not a crawler, fuzzing engine, security-check engine, proxy manager, or scheduler.

## Request path and authorization order

Every `httpengine.Request` contains a mandatory `ProjectID`. For each attempt and each redirect hop, the engine performs the following sequence: normalize the target; authorize the hostname/URL with R1 `ActionHTTP`; wait for the local rate limiter; acquire a bounded concurrency slot; resolve through the controlled resolver; reject unsafe addresses; authorize the pinned address with R1 `ActionConnect`; then issue the HTTP request.

```text
project-scoped request
  -> R1 ActionHTTP authorization
  -> local rate limit
  -> bounded concurrency slot
  -> controlled DNS resolution
  -> destination safety validation
  -> R1 ActionConnect authorization for the resolved address
  -> validated direct dial or explicit proxy transport
  -> bounded response and redacted R2 observation
```

The order intentionally places authorization before waiting, resolution, and network I/O. A cancellation is honored before the first policy decision and while waiting for a rate or concurrency slot. Retries execute the same complete path; they cannot inherit an earlier authorization or bypass a rate/concurrency control.

## Destination, redirect, and TLS controls

The resolver result is validated before dialing and is pinned into the transport dial path, preventing a second resolver lookup from changing the direct connection target. The default destination policy rejects unspecified, loopback, link-local, multicast, private, CGNAT, protocol-assignment, documentation, benchmarking, and other reserved test ranges, including IPv4-mapped IPv6 representations. `AllowPrivate` is a local-test/internal-lab override and must not be enabled for ordinary external targets.

Redirects are manual. Every `Location` is parsed and processed as a new R1/DNS/destination-validation attempt. A policy failure during a redirect becomes `ErrRedirectDenied`. A collector may additionally supply a bounded `RedirectValidator`; the migrated probe and content collectors retain their same-host rule, while JavaScript collection retains its same-host script fetch rule. Per-request response and redirect limits preserve the collectors’ prior resource bounds.

TLS uses Go certificate verification with TLS 1.2 as the minimum version. The engine does not expose an insecure-TLS option. An untrusted certificate is an error rather than a recoverable or silently downgraded condition.

## Connection lifecycle and concurrency

`NewEngine` creates one reusable `http.Transport` and one `http.Client`; it never creates a client per request. Keep-alive and HTTP/2 are enabled. Default pool controls are a 30-second idle timeout, 32 total idle connections, and four idle connections per host. Callers may set `IdleConnTimeout`, `MaxIdleConns`, and `MaxIdleConnsPerHost`; invalid bounds fail closed when a request is attempted. `CloseIdleConnections` is the explicit lifecycle cleanup method used by the scan orchestration path.

The engine also has a cancellation-aware local concurrency gate. It defaults to ten in-flight request attempts and accepts a bounded configuration of one through fifty. The migrated scan path passes the existing `--web-concurrency` value to retain the Phase 2–3 concurrency contract.

## Rate limiting and retry policy

The engine always has a local interval limiter. Its conservative default is one request every 50 milliseconds (20 requests/second). `wraith scan` exposes `--web-rate` with a bounded range of one through twenty requests/second and keeps its existing content/JavaScript per-host limiter as an additional collector control. The limiter is local to one engine/process; it is not a distributed quota system.

`DefaultRetryPolicy` performs exactly one attempt. Retrying is opt-in and capped at three attempts. A retry policy can declare an initial/max backoff, optional jitter, retryable HTTP statuses, and whether unsafe methods are permitted. By default only `GET`, `HEAD`, and `OPTIONS` are eligible. `POST`, `PUT`, `PATCH`, and `DELETE` are not replayed unless a caller explicitly sets `AllowUnsafeMethods`. The migrated probe and JavaScript readers retain their prior one-retry-on-temporary-error behavior through a per-request safe-method policy; content discovery does not opt in.

## Explicit proxy contract

`Config.ProxyURL` is the only proxy input. Environment proxy variables are not read. Only syntactically valid `http://` or `https://` proxy URLs are accepted; an invalid explicit value fails closed with a generic error that does not echo the proxy authority or credentials. HTTP proxying and HTTPS CONNECT are delegated to Go’s hardened transport. Proxy credentials in the URL are sent only as proxy authentication by the transport and are never included in Wraith observations or configuration errors.

R1 authorization always applies to the **actual target**, not the proxy. The configured proxy authority is the sole transport dial exception to validated target pinning; target authorization, resolution safety, and connection authorization execute before any proxy connection. Consequently, an unauthorized target cannot be reached by configuring a proxy. An explicitly trusted proxy remains a transport trust boundary: it can observe traffic routed through it, so operators must select and secure it separately.

## Evidence and collector migration

Request headers, cookies, bodies, proxy credentials, and response bodies are not persisted by the engine. Optional R2 observation emission stores bounded metadata only and sends response headers through the existing sensitive-header redactor before persistence. `Authorization`, cookies, API-key variants, bearer-token-style headers, and proxy authorization are redacted.

| Collector | R3 status | Preserved behavior |
| --- | --- | --- |
| `internal/probe` | Migrated | Read-only metadata, same-host redirects, response cap, and a safe timeout retry. |
| `internal/contentdiscovery` | Migrated | Random soft-404 baseline, same-host redirects, wordlist/path constraints, and bounded per-host rate. |
| `internal/jsanalysis` | Migrated | Same-origin script selection, file cap, safe timeout retry, redacted potential-secret evidence. |
| `internal/enum` CRT/VT providers | Intentional exception | Provider API traffic and credentials need a separate provider-policy/terms design; it is not target-web collection. |
| Local discovery, port scan, and Nuclei adapters | Intentional exception | They use local sockets or optional subprocesses and require their own reviewed policy adapters. |

## Verification and known limitations

The transport suite uses localhost fixtures only and covers policy-before-I/O, DNS destination checks, private/reserved addresses, IPv4-mapped IPv6, IPv6 literals, redirects, proxy routing/authentication, proxy denial, TLS verification, response caps, redaction, cancellation, concurrency, connection reuse, safe retries, unsafe-method non-replay, and R2 observation behavior. Fuzz targets cover URL parsing, redirects, destination validation, header processing, and proxy/request configuration. Benchmarks characterize request creation, target validation, destination validation, header redaction, metadata processing, connection reuse, and limiter overhead.

R3 does not add proxy credential storage, proxy health checks, a cross-process rate limit, scope-authoring CLI workflows, provider-policy enforcement, subprocess policy adapters, crawling, fuzzing, security checks, scheduling, or R4 behavior.
