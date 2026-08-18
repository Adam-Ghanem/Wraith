# R8 — Evidence-Led Security Validation Specification

## Purpose

R8 turns bounded web response evidence into reproducible, reviewable security-validation observations. It supports only non-destructive checks for response security headers, CORS policy, cookie attributes, error disclosure, and information disclosure. It does not exploit, authenticate, submit forms, mutate state, guess credentials, brute force, spray passwords, or execute payloads.

## Evidence and transport boundary

The validation engine receives an explicit project and an explicit existing R2 endpoint selected from that project. A validator consumes bounded response metadata and body-derived disclosure indicators only. Where an R8 command refreshes an endpoint, it performs one bounded safe-method request through the existing R3 `httpengine.Client`; R3 applies R1 target, redirect, and resolved-destination authorization. R8 introduces no alternate HTTP client, browser, resolver, socket, dialer, subprocess, remote API, proxy route, or crawler.

## Validator contract

Each validator implements a narrow `Validator` interface with a stable identifier and version, deterministic applicability rule, and deterministic result order. Validators emit a `ValidationResult` that records the observed condition, exact evidence references, and a reproducibility key derived from stable project, endpoint, validator, rule, and normalized evidence metadata. A result is never an exploit claim.

The initial validator set is limited to the following categories:

| Category | Bounded evidence examined | Explicit limitation |
| --- | --- | --- |
| Security headers | Selected response-header presence and safe normalized directives | Does not claim a configuration is exploitable. |
| CORS | `Access-Control-Allow-*` metadata on the observed response | Does not send origin probes or credentialed cross-origin requests. |
| Cookie attributes | Names and presence of `Secure`, `HttpOnly`, and `SameSite` attributes, never values | Does not authenticate or replay cookies. |
| Error disclosure | Bounded text indicators of stack traces, framework diagnostics, or server exceptions | Does not inject malformed input to generate errors. |
| Information disclosure | Bounded header and body indicators such as version banners or internal-path patterns | Does not fetch extra files or expand scope. |

## Finding lifecycle and persistence

R8 stores project-scoped, append-only validation evidence and a deterministic finding identity. Findings begin in `observed`; later operator-controlled lifecycle handling may mark them `accepted`, `resolved`, or `false_positive`. The engine never auto-confirms exploitability or creates a lifecycle transition from a response alone. Findings must carry validator/rule version, evidence references, observation time, and a reproducibility key. Raw bodies, credentials, request values, cookie values, authorization material, and arbitrary headers are excluded from persistence.

## Required controls

Every run requires `--authorized`, `--project`, an explicit endpoint selection, a timeout, total-duration bound, response-size bound, rate, concurrency, and maximum request count. R2 reads and writes are project-filtered. Cross-project endpoint selection fails before a request. Validation results are sorted deterministically. Cancellation propagates to all work.

## Stop condition

R8 ends after evidence-led validation results and lifecycle-ready findings are persisted on its own feature branch with unit, project-isolation, policy-denial, bounded localhost integration, fuzz, benchmark, migration, race, egress, and full quality coverage. It does not start R9.

## Current implementation boundary

The in-progress R8 branch contains the deterministic passive validator package, selected-project `wraith validate` command with a one-request hard limit and dry-run mode, R3-only refresh path, and the SQLite migration that adds a dedicated redacted `validation` observation kind. The remaining verification and review requirements in the stop condition remain mandatory before R8 can be declared complete.
