# T2 Security Review

T2 is an offline, deterministic target-boundary authority. It performs no HTTP request, DNS lookup, socket dial, subprocess execution, scheduler action, or scan. R3 remains the transport and DNS owner.

| Threat | T2 control | Result |
|---|---|---|
| Target normalization bypass | HTTP(S)-only canonical parser, fragment removal, credential rejection, explicit default ports, traversal/encoded-dot rejection. | Fail closed. |
| Lookalike/wildcard escape | Exact host equality or dot-boundary subdomain matching; wildcard form excludes the base host itself. | No suffix/sibling match. |
| Scope expansion | Immutable version ID, canonical fingerprint, typed rules, and deny-overrides-allow evaluation. | New rules require a new version. |
| Authorization misuse | Exact T1 project and scope-reference binding plus T1 expiry/revocation/fingerprint validation. | Fail closed. |
| Forged SQLite metadata | Storage reconstructs rules; authority recomputes the canonical fingerprint before a decision. | Forged fingerprint is rejected. |
| Redirect/DNS destination escape | The authority can evaluate each independently supplied target; R3 continues to resolve and invoke its gateway per destination. | No inherited authorization. |

## Audit classification

R1 `internal/policy` is the existing authorization decision seam during migration. R3 `internal/httpengine` redirect and resolved-IP checks are **transport safety** and remain defense in depth. T2 is the new authoritative scope model; no legacy check has been removed until a compatible adapter and regression coverage are complete.

## Egress source audit

The T2 authority, scope CLI, and T2 storage adapters were searched for `net/http`, `http.Client`, `net.Dial`, `net.Listen`, `net.Resolver`, `LookupHost`, `LookupIP`, `os/exec`, and command-execution primitives. No prohibited primitive was found. T2 remains a decision and persistence layer only.

## Known limitation

The `wraith scope` CLI and the active-assessment authorization seam now consume persisted T2 scope versions and valid T1 records. Other legacy active paths retain their established R1/R3 checks until they can be migrated through the same authority without a compatibility bypass. This limitation is explicit; no claim is made that every historical path already consumes T2.
