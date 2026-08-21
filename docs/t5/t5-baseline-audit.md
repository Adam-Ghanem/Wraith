# T5 Baseline Audit: Central Outbound Gateway

## Purpose and Boundary

T5 defines an **outbound policy boundary** for the active R15 assessment paths. It is deliberately a policy and delegation layer, not a replacement for R3. The boundary accepts a short-lived operation only after T1 authorization, T2 scope, T3 decision provenance, and T4 derived trust can be validated. It then audits the allow decision and delegates the already-approved request to the injected R3 transport.

| Area | Classification | T5 disposition |
|---|---|---|
| `internal/assessmentbuiltin` crawl adapter | Centralized active path | Constructs one operation and delegates through `outbound.Client` before R3. |
| `internal/assessmentbuiltin` smart-discovery adapter | Centralized active path | Constructs one operation and delegates through `outbound.Client` before R3. |
| `internal/httpengine` | Canonical R3 transport owner | Retained unchanged; T5 injects and delegates to it, but never constructs a transport. |
| Existing CLI web, fuzz, validation, injection, probe, and discovery commands | Legacy active paths | Explicitly out of T5's initial capability registry; they receive no T5 capability or implicit approval. |
| Tests that construct R3 engines | Test-only seams | Not production dispatch paths. |

The source audit found multiple legacy R3 request consumers. T5 does not make a false claim of whole-repository interception. The first migration is intentionally limited to the two R15 HTTP-read owners, whose ownership is explicit in `DefaultRegistry()`. Any future migration must add a distinct capability, owner, regression tests, audit review, and this inventory update.

## Ownership Map

| Operation | Capability | Owner | Request limits | Transport owner |
|---|---|---|---|---|
| `crawler_http_read` | `assessment-crawl-read` | `r4.crawler` | GET/HEAD only; no body, authorization, or cookie headers | R3 `httpengine.Client` |
| `discovery_http_read` | `assessment-discovery-read` | `r11.2.smart_discovery` | GET/HEAD only; no body, authorization, or cookie headers | R3 `httpengine.Client` |

Credential-looking material is rejected **before target parsing**. Therefore, a URL containing user information is not handed to the scope parser or transport as an ordinary destination failure.

## Egress Non-Claims

T5 does not add or own a DNS resolver, socket, HTTP client, subprocess, scanner, scheduler, worker, credential store, redirect engine, or automatic target expansion. It does not authorize the legacy paths listed above, and it does not assert that a generic network primitive elsewhere in the repository is automatically governed by this initial R15-only migration.
