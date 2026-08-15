# Phase 1 Prompt Reconciliation

**Status:** Reviewed against the attached `wraith_phase1_prompt.md` on 2026-08-15.

The attached build prompt is broader than the previously frozen Wraith Phase 1 scope. This document records which requests are implemented, which compatible improvements are being applied, and which requests remain deliberately deferred. The frozen scope remains authoritative: one explicitly selected local IPv4 interface/CIDR, bounded ARP, curated top-100 TCP connect checks, bounded read-only metadata, JSON and terminal output, and owned or explicitly authorized targets only.

## Compatibility matrix

| Prompt request | Decision | Rationale or implementation note |
|---|---|---|
| TCP connect checks on a built-in curated top-100 list | Implemented | Already present. The list is versioned, finite, and tested for exactly 100 unique ports. |
| Worker pool, configurable concurrency, timeouts, context cancellation | Implemented | Already present. The concurrency ceiling is bounded at 100 and the default connect timeout is 2 seconds. |
| Basic banner capture after connect | Implemented | Already present as bounded, sanitized, read-only metadata. |
| ARP discovery using a Go library | Implemented | The Linux adapter uses `mdlayher/arp`; no shell fallback is used because shelling out would add an unnecessary command-execution boundary. |
| Clear Linux privilege error | Implemented | Permission failures are reported as an operator-readable ARP permission error rather than a panic. |
| Banner-pattern service guessing | Implemented | Added as a conservative refinement of read-only service metadata. It does not authenticate, submit data, or make vulnerability claims. |
| JSON and terminal output | Implemented | Both representations describe the same bounded run. |
| Large-subnet warning/confirmation | Implemented | Candidate limits above 256 require an explicit `--confirm-large-subnet` acknowledgement and produce a warning before discovery. |
| `--json` and `--subnet` convenience flags | Implemented as aliases | They do not widen scope: `--subnet` still requires an explicitly selected local interface, and `--json` only selects output format. |
| Automatic local-subnet detection | Deferred and rejected for Phase 1 | The frozen boundary requires explicit interface and CIDR selection. Auto-detection could select the wrong network and would weaken fail-closed behavior. |
| Optional `--ports` mode that omits TCP checks | Deferred and rejected for Phase 1 | The frozen Phase 1 run contract includes bounded TCP checks after discovery. A mode that silently omits them would create a different, undocumented scope. |
| Local OUI vendor database | Deferred and rejected for Phase 1 | Vendor enrichment was explicitly excluded from the frozen Phase 1 boundary. MAC addresses remain direct ARP observations only. |
| TTL-based OS heuristic | Deferred and rejected for Phase 1 | TTL inference is an additional heuristic and was explicitly deferred. Phase 1 does not claim OS identification. |
| Full OS fingerprint database | Rejected | It is outside the frozen scope and would create inference and maintenance obligations. |
| CVE, vulnerability, web, Nmap, Nuclei, database, dashboard, scheduling, or external API features | Rejected | These remain explicit Phase 1 exclusions. |
| `zerolog` dependency | Not added | This small Linux CLI uses bounded error returns and standard output contracts without an external logging dependency. Adding a logger does not authorize new behavior or improve the network boundary. |
| Exact package names from the prompt | Not treated as a behavioral requirement | The existing package split keeps scope/configuration, discovery, probing, metadata, output, and models isolated. Renaming packages would be a cosmetic refactor, not a safety or correctness fix. |

## ARP library trade-off

Wraith uses `github.com/mdlayher/arp` because it keeps ARP behavior inside a typed Go boundary, avoids shell command execution, exposes explicit deadlines, and can be tested behind an internal resolver interface. A shell-out fallback to `arp-scan` would depend on host installation, command-line parsing, executable lookup, and privilege behavior; it would also make the fail-closed target boundary harder to prove. For those reasons, Phase 1 reports the library error clearly instead of silently invoking another scanner.

## Linux permission behavior

ARP packet access commonly requires privileges that ordinary TCP connect calls do not. The implementation attempts to open the ARP client only after interface, CIDR, and authorization validation. If Linux denies packet access, Wraith returns an error explaining that ARP discovery may require the least privilege available on the host, such as the capability configuration approved by the operator, or controlled elevated execution. It does not retry with another tool and does not continue with a broader fallback.

## Testing consequence

Pure logic tests cover port-list integrity, scope validation, banner sanitization, service guessing, output serialization, interface matching, bounded ARP enumeration, worker-pool limits, cancellation, and CLI validation. An actual network run remains an operator-controlled activity and requires an explicit interface, CIDR, and current ownership or authorization confirmation.
