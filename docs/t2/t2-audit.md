# T2 Architecture Audit

## Verified ownership seams

| Area | Classification | T2 treatment |
|---|---|---|
| `internal/policy` target parsing and evaluator | Legacy authoritative R1 scope semantics | Preserved during migration; T2 does not delete or silently fork it. |
| `internal/httpengine` per-hop target authorization | R3 transport safety | Preserved. R3 remains the only HTTP/DNS/dial owner. |
| `internal/httpengine` resolved IP destination policy | R3 transport safety | Preserved; T2 may evaluate an R3-supplied destination without resolving it. |
| `assessmentAuthorizer` | Active lifecycle seam | Identified as the narrow compatible adoption point; no new execution path introduced. |
| `internal/config` local CIDR validation | Phase-1 local discovery safety | Defense in depth; not web target-scope semantics. |
| `internal/scope` | T2 authoritative model | Pure deterministic target-boundary decisions, T1 binding, canonical fingerprint verification, and immutable project versions. |

## Egress audit

The T2 scope package contains no `net/http`, `http.Client`, `net.Dial`, `net.Listen`, `net.Resolver`, `LookupHost`, `LookupIP`, `os/exec`, or shell execution. It parses already-supplied target strings and evaluates typed data only.

## Migration status

T2 adds a safe local command family and immutable scope persistence. Existing R1/R3 checks are intentionally retained until an adapter can bind every active operation to a persisted T1 authorization reference without creating a compatibility bypass. This is an explicit safety constraint, not a claim that migration is complete.
