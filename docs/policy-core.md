# R1 Policy Core

**Status:** Implemented on `feature/r1-policy-core`; not merged into `main` by this document. R1 provides a deterministic authorization decision boundary. It **does not** add a network scanner, DNS resolver, HTTP client, scheduler, API, worker, or dashboard.

## Purpose and invariant

The `internal/policy` package answers one narrowly defined question:

> Is this exact normalized target and action currently authorized for this project?

The evaluator is project-scoped, has no network I/O, and **fails closed**. A matching `deny` rule overrides every matching `allow` rule. If no active `allow` rule matches, the decision is denied. An expired or revoked authorization is denied before rule matching; a revoked rule never grants access.

| Control | R1 behavior |
| --- | --- |
| Project isolation | The evaluator loads exactly one active scope for the requested `ProjectID`; a returned project mismatch is denied. |
| Versioning | Each `ProjectScope.VersionID` is immutable in SQLite. A changed scope is saved as a new version and atomically becomes the active version for that project. |
| Authorization lifecycle | Every scope has an owner-bearing authorization record with approved actions, UTC expiry, and revocation. |
| Decision trace | Every result contains the normalized target, action, reason, and deterministically ordered matching rules. |
| Default | No active matching allow rule means `ErrOutOfScope`. |

## Policy model

`ScopeRule` uses strong types for effect, target type, protocol, action, and inclusive port ranges. Rule values are validated when a scope is saved and again when it is loaded from persistence. The evaluator accepts only `resolve`, `connect`, `http`, `scan`, and `enumerate` action names; adding an action requires an explicit code and test change.

| Target type | Rule grammar | Matching semantics |
| --- | --- | --- |
| `domain` | `example.com` or `*.example.com` | Exact domains match only themselves. A wildcard matches descendants at any depth but never its root. Matching occurs on whole DNS-label boundaries, not string substrings. |
| `url` | Absolute `http` or `https` URL | Scheme, host/IP, effective port, and normalized path boundary must match. `/api` matches `/api` and `/api/v1`, not `/apix`. Query and fragment are not destination identity. |
| `ipv4_cidr` | Canonical IPv4 address or CIDR | The normalized IPv4 address must be contained by the canonical prefix. IPv4-mapped IPv6 targets are unmapped before matching. |
| `ipv6_cidr` | Canonical IPv6 address or CIDR | The normalized IPv6 address must be contained by the canonical prefix. IPv4-mapped addresses cannot bypass into the IPv6 rule space. |

Empty port/protocol lists do not add a restriction. A non-empty port list requires a concrete port within one inclusive range. A non-empty protocol list must match the URL scheme or the current `connect`/`scan` TCP interpretation. R1 deliberately has no implicit UDP transport behavior.

## Target normalization and parser safety

`ParseTarget` accepts an explicit hostname/IP, hostname/IP plus port, or absolute HTTP(S) URL. It lowercases ASCII hostname labels, removes one trailing DNS root label, applies HTTP/HTTPS default ports, normalizes a missing URL path to `/`, unmaps IPv4-mapped IPv6 addresses, and rejects ambiguity instead of guessing.

The parser rejects whitespace, userinfo, non-HTTP URL schemes, percent-encoded hostnames, malformed authority, port `0`, out-of-range ports, a host/path string with no scheme, and non-ASCII Unicode hostnames. **IDNA conversion is intentionally not performed in R1**: callers must supply an already ASCII/punycode hostname, which prevents the policy layer from silently changing a target identity.

## Redirects, SSRF, and DNS rebinding

R1 introduces `OutboundTargetGateway`, currently an authorization-only seam over `PolicyEvaluator`. A redirect destination has no inherited approval: every redirect target must call `Authorize` independently. Likewise, the hostname decision and a later resolved IP decision are distinct inputs. R3 now reauthorizes every resolved destination immediately before connection and supplies DNS resolution pinning/private-reserved-address policy in the migrated target-web

This boundary deliberately does **not** claim that DNS rebinding or SSRF is solved in R1. The current result is architectural: future network code has a single policy contract and tests demonstrate that a hostname allow does not automatically authorize `127.0.0.1`, a redirect target, or an unrelated IP.

## Persistence

Migration `004_policy_core.sql` adds immutable scope versions, rules, and a one-row active scope pointer per project to the existing SQLite database. The persistence adapter stores only policy metadata: identifiers, target rules, ports/protocols, timing, and approved actions. It stores neither credentials nor request bodies. SQLite persistence was retained; no PostgreSQL, Redis, API, scheduler, or worker system was added.

## Test and performance evidence

The policy suite is table-driven and covers exact/wildcard labels, suffix confusion, URL destination/path parsing, explicit/default ports, protocol/action constraints, IPv4/IPv6 CIDRs, mapped IPv6, project mismatch, expiration, revocation, deny-overrides-allow, redirect escape, and post-resolution reauthorization. Three bounded fuzz targets exercise target parsing, rule validation, and evaluation of parsed hostile input without a panic.

The following measurements were collected locally on Linux/amd64 with Go 1.23.12 and the benchmark’s in-memory immutable scope store. They measure policy evaluation only, not SQLite load, DNS, or network activity; they are characterization data rather than a production service SLA.

| Rules in active scope | Time/op | Heap bytes/op | Allocations/op |
| ---: | ---: | ---: | ---: |
| 100 | 6,360 ns | 320 B | 4 |
| 1,000 | 55,262 ns | 343 B | 4 |
| 10,000 | 585,071 ns | 3,140 B | 15 |

## Explicitly deferred

R1 intentionally leaves the following work to later reviewed stages: scanner integration, existing HTTP-call-path migration, DNS lookups and connection pinning, redirect transport handling, private/reserved-address filtering, resource budgets, durable audit events, organization/user/RBAC records, HTTP API, background execution, PostgreSQL/Redis, and live dashboard data. R2 should next introduce normalized project asset identities and immutable observations; R3 should move existing outbound paths through the gateway only after the required DNS/HTTP/budget design is approved.
