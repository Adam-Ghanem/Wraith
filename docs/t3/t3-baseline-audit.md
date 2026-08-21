# T3 Baseline Audit — Security Trust and Operational Authority

**Baseline:** `origin/main` at `26f9eed250ffeb2537af28008e8fa6cb2e49f514`
**Branch:** `feature/t3-security-trust-hardening`
**Status:** Pre-code audit; no active capability changed.

## Scope and decision

T3 hardens trust, local authorization evidence, auditability, execution authorization, local data handling, release verification contracts, privilege diagnostics, and CI controls. It does not add a scanner, exploit workflow, HTTP client, resolver, socket layer, scheduler, worker, credential store, or automatic privilege elevation.

`--authorized` remains an operator acknowledgement. It is neither a proof of ownership nor a substitute for a persisted lifecycle record, scope decision, or execution eligibility decision.

## Ownership map

| Capability | Current owner | Entry point | Existing enforcement | T3 direction |
|---|---|---|---|---|
| Operator acknowledgement | CLI flag parsing | Active command parsers | `--authorized` checks | Preserve as acknowledgement only; expose assurance state separately. |
| Persisted authorization lifecycle | `internal/authorization`, `internal/storage/authorization.go` | `wraith authorization` | Canonical T1 record validation, expiry/revocation, fingerprint and project/scope binding | Reuse; add append-only audit events, assurance classification, and auditable rejection reasons. |
| Target-scope membership | `internal/scope` | `wraith scope`, assessment authorizer | Canonical T2 version fingerprint, typed rules, deny precedence, T1 binding | Reuse without rule duplication; central gate delegates to this authority. |
| Legacy policy compatibility | `internal/policy` | R1 gateways and pre-T2 records | Project scope, action checks, destination checks | Retain as explicit compatibility route; no fail-open fallback. |
| HTTP, DNS, redirects, sockets | `internal/httpengine` | R3 engine construction | Gateway authorization, destination checks, redirect revalidation, limits | Remain the only transport owner; T3 supplies no second client/resolver/socket. |
| Assessment execution | `internal/assessmentexec` | `wraith pentest assessment run` | Recheck callback, R10.5 budget/rate/concurrency, adapter registry | Adopt a single local execution gate at the existing recheck seam. |
| Campaign and adapter orchestration | R14/R15 assessment seams | Campaign/assessment commands | Typed owner registry and R13.2 lifecycle | Reuse one gate; reject task identity and scope-chain mismatches. |
| Optional subprocesses | `internal/executil` with `portscan`/`vulncheck` consumers | Optional Phase-4 wrappers | Direct executable path, context cancellation, fixed downstream args, output cap | Harden at the shared boundary; never accept a shell string or executable path from an untrusted caller. |
| Local persistence | `internal/storage` | SQLite migrations and repositories | Parameterized queries, project keys, per-model fingerprints | Add only additive integrity/audit structures and classification checks. |
| Release integrity | Makefile and release docs | `make release`, checksums | Build metadata and SHA256SUMS only | Add a verification/signing contract without committing private material or inventing cryptography. |
| Phase-1 privileges | `internal/cli/discover.go` | `wraith discover` | Explicit permission failure text | Add deterministic diagnostics only; never run sudo or silently elevate. |

## Trust chain

The T3 execution decision must form one explicit chain:

```text
operator acknowledgement
  -> persisted T1 authorization record
  -> canonical T2 scope version and fingerprint
  -> canonical target decision
  -> task/assessment identity and project binding
  -> R10.5 budget, concurrency, and rate eligibility
  -> R3 transport reauthorization and destination validation
```

Every link is fail-closed. T3 must reject missing, expired, revoked, cross-project, fingerprint-mismatched, scope-mismatched, target-mismatched, or task-identity-mismatched input. The central gate performs no network I/O and does not replace R3.

## Egress and process baseline

| Occurrence class | Authorized owner | T3 constraint |
|---|---|---|
| HTTP/DNS/dial/redirect behavior | R3 `internal/httpengine` | No new T3 transport or resolution call. |
| Nmap/Nuclei process execution | `internal/executil` and fixed optional wrappers | No shell interpretation; T3 may add policy checks only at the existing shared boundary. |
| Provider/environment API key use | Existing Phase-2 source integrations | No new T3 provider integration and no persistence or logging of keys. |
| ARP/raw privilege requirement | Existing Linux discovery adapter | Diagnostics only; no automatic elevation or fallback scanner. |

## Initial risks and required tests

The baseline contains mature T1/T2/R3 controls, but a full execution chain is currently assembled in CLI callbacks and assessment execution dependencies rather than being represented by one named gate. T3 must make that dependency explicit and test rejection for every broken link. Authorization audit records are also currently lifecycle-state records, not an append-only event trail.

The first T3 tests must be written before implementation and must prove: expired/revoked/missing authorization rejection; T1/T2 project/scope/target/fingerprint binding; adapter task identity rejection; budget ineligibility; append-only event fingerprint integrity; cross-project read refusal; secret-like audit/classification input rejection; and no network behavior in pure authorities.

## Explicit limitations at audit time

This audit does not claim cryptographic real-world ownership proof. Existing release artifacts are checksummed but not signed. Existing T1/T2 adoption has a documented legacy R1 compatibility route for records without a persisted T2 version. T3 must preserve that route only where its existing R1 validation applies and must not translate absence of T2 data into an allow decision.
