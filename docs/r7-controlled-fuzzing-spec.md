# R7 Controlled Fuzzing Specification

## Purpose

R7 provides bounded **generic parameter mutation and response intelligence** for an explicitly selected project endpoint and parameter. It is a local CLI workflow, not a scanner, crawler, credential-testing system, vulnerability validator, or exploitation engine. R7 stops at `FuzzObservation`; R8, findings, risk scoring, validation, and automated exploitation remain out of scope.

## Non-Negotiable Active-Request Boundary

Every non-dry-run request is submitted through `httpengine.Client.Do`, backed in production by the existing R3 `httpengine.Engine`. R7 must not import or instantiate an HTTP client, resolver, socket, dialer, proxy transport, browser, JavaScript runtime, or subprocess. R3 retains R1 authorization for every initial and redirect target, DNS/destination validation, IPv4-mapped IPv6 normalization, proxy policy, response bounds, retries, transport rate limiting, and concurrency control.

R7 adds a workload ceiling around R3; it does not create a competing transport rate limiter. A context cancellation must stop planning, scheduling, engine calls, analysis, and persistence without orphaned worker goroutines.

## Target Selection and Project Isolation

The CLI requires `--project`, `--authorized`, an exact canonical R2 `--endpoint` identity, an explicit `--parameter`, its `--location`, and a predefined `--profile`. It loads only the named project’s R2 endpoint and parameter records and rejects an endpoint/parameter mismatch, another project’s identity, missing authorization, duplicate selection, or a profile that exceeds configured limits.

R7 never expands a project inventory automatically. It does not fuzz every discovered endpoint, every parameter, an inferred route, a wordlist, or recursively discovered content. R5/R6 data only helps an operator choose the exact R2 identity; it is not permission to create extra targets.

## Request Templates and Supported Locations

| Location | Template source and mutation rule |
| --- | --- |
| Query | The canonical endpoint URL; only the selected query name is replaced, with all known non-selected names preserved without values. |
| Path | An explicit `{name}` path placeholder in the selected endpoint URL. No path enumeration, traversal list, or route discovery is permitted. |
| JSON | An explicitly supplied bounded local JSON body template; only the selected, bounded-depth field path changes and valid JSON is preserved. |
| Form | An explicitly supplied bounded local `application/x-www-form-urlencoded` or multipart field template; file upload and generated files are forbidden. |
| Header | A selected non-sensitive header in an explicit request template. Authorization, Cookie, Set-Cookie, Proxy-Authorization, and credential-like names are always rejected. |

R2 does not retain query/body values. R7 therefore never invents or persists such values. Where a value-bearing template is required, it must be supplied explicitly as bounded local operator input and is used only in-memory for the invocation.

## Mutations and Determinism

`MutationProvider` implementations are internal only and return generic, bounded values with an ID, category, safety class, input metadata, and deterministic metadata. Profiles are `minimal`, `boundary`, `encoding`, `type`, and `combined`; each is a stable deduplicated union with a fixed maximum count.

The allowed categories are boundary, empty, length, numeric, boolean, encoding, unicode, special-character, type-confusion, and structured. Mutations include empty/short strings, bounded length values, finite integer boundaries, booleans, null, an empty array, a single-item array, URL and double encoding, Unicode, whitespace, and reserved/separator characters. They do not contain exploit payloads, credential guesses, unbounded combinatorics, enormous strings, directory brute force, recursive discovery, timing-delay payloads, or destructive actions.

## Method, Request, and Job Limits

Safe methods are GET, HEAD, and OPTIONS. POST, PUT, PATCH, and DELETE require both explicit unsafe-method enablement and a separate confirmation flag on every invocation; default R3 retry behavior remains non-replaying for unsafe methods. Every plan has bounded request count, mutation count, body bytes, mutation bytes, header count, JSON depth, per-request timeout, overall duration, requested R3 concurrency, and requested R3 rate interval.

The local job state machine is `pending`, `running`, `completed`, `failed`, or `cancelled`. It is in-memory for R7. No Redis, queue, distributed worker, autonomous scheduling, or restart resume is introduced. In particular, state-changing methods are never resumable.

## Response Intelligence and Evidence

R7 may optionally request one baseline through R3, then compares mutation responses by status, content type, bounded length, selected safe headers, deterministic body fingerprint, reflection indicators, generic error indicators, redirect metadata, and normal elapsed duration. A reflection indicator records where a mutation marker appeared; it never claims XSS. Error and baseline deltas are observations, never vulnerabilities.

R2 stores a typed, append-only `fuzz` observation linked to the existing canonical endpoint. Persisted payloads contain only redacted structural metadata: mutation ID/category/safety class, status/content type/length, bounded timing, fingerprint, baseline deltas, reflection location, generic error classes, and redirect count. Request bodies, response bodies, Authorization/Cookie values, tokens, passwords, API keys, source templates, and mutation values are not persisted.

## CLI and Dry Run

`wraith fuzz` supports project, authorization, endpoint, parameter, location, profile, rate, concurrency, max requests, timeout, max duration, JSON output, and `--dry-run`; bounded local template flags are added only where JSON/form/header input requires them. `--dry-run` builds and prints the deterministic plan, selected target, profile, mutation IDs/categories, request estimate, method policy, and limits without constructing or invoking R3.

## Verification and Stop Condition

R7 requires unit, isolation, authorization, redirect/destination, sensitive-header, size, request-explosion, cancellation, safe-method, localhost-only integration, fuzz, benchmark, race, egress-audit, and full-project quality coverage. The R7 package must show no direct HTTP client, DNS, socket, dialer, or alternate transport path. R7 ends after its feature branch is committed and pushed. **R8 is not started.**
