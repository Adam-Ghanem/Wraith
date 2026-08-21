# T6 Architecture: Central Egress Adoption and Explicit Legacy Denial

## Decision

T6 makes **T5 the only supported target-web dispatch boundary** in the repository’s active CLI surface. The existing assessment and campaign R15 paths remain the supported path because they already provide a fresh T4 trust context, R10.5 controls, T2 policy authority, T3 audit store, and injected R3 transport. T6 does not invent these authorities for legacy commands.

| Command/path category | T6 behavior | Reason |
|---|---|---|
| `pentest assessment` and `pentest campaign` R15 dispatch | Allowed through existing T5 adapter integration | Each dispatch has task-bound T4 trust and T3 audit lineage. |
| Legacy HTTP command with no `--dry-run`, including `discover TARGET` smart discovery | `ErrLegacyOutboundBlocked` | Its direct R3 path lacks a reviewed T5 capability and task-bound T4 trust. |
| Legacy dry-run command | Allowed to retain local validation/planning only | Dry-run must not dispatch HTTP, DNS, sockets, subprocesses, providers, or evidence writes. |
| `scan` provider/DNS operation | `ErrProviderOutboundBlocked` | CRT.sh, VirusTotal, and DNS enumeration have no T5-compatible provider capability and may include API-key headers. |
| `scan --use-nmap` or `--use-nuclei` | `ErrSubprocessOutboundBlocked` | Existing optional external tools cannot carry the current HTTP-read T5 operation contract. |
| Phase 1 default local discovery | Retained local-only exception | It is governed by its separate explicit local interface/CIDR policy, not target-web egress. |

The root `Run` dispatcher invokes `t6OutboundBlock` **before command parsing**, database opening, transport construction, provider setup, and subprocess lookup. The errors are typed sentinels with constant secret-free messages. This ensures malformed arguments cannot select an alternate legacy code path.

## Authority Flow

```text
assessment or campaign task
  -> T1 active authorization
  -> T2 scope decision
  -> T3 execution-eligible assurance
  -> T4 derived task trust
  -> T5 capability, scope, budget, audit decision
  -> injected R3 transport
```

T6 deliberately does not rebuild this chain in standalone legacy commands. A future migration must establish an explicit capability, owner, safe request contract, T4 trust producer, T3 audit event, control ownership, regression coverage, and inventory update before its root block can be removed.

## Redirects and DNS

R3 continues to own request transport, resolution pinning, resolved-destination validation, and manual redirect handling. The existing R3 client returns the first redirect response instead of automatically following redirects. T6 does not add a redirect engine, a resolver, or a socket layer.
