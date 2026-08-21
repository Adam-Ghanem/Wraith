# T6 Outbound Capability Inventory

## Audit Method and Decision Rule

This inventory is based on source inspection of production and test Go files plus the static web application. Searches covered `net/http`, `net`, `net/url`, R3 construction, R3 client injection, resolver calls, subprocess execution, and browser outbound primitives. A textual match is not automatically an egress path: URL/header models and test fixtures are classified separately from code that can create network activity.

> **T6 decision rule:** a production path is permitted only when it is the R3 transport owner, a T5-governed dispatch path, a documented local-only capability, or an explicit temporary blocked exception. There is no implicit legacy permission.

| Component | File/package | Primitive | Protocol | Current owner | T1–T4 / scope path | T5 status | T6 decision |
|---|---|---|---|---|---|---|---|
| R3 transport | `internal/httpengine` | `net/http`, resolver, pinned dialer | HTTP(S), DNS, TCP/TLS | R3 | R3 invokes T2 target gateway for original, redirect, and resolved destinations | Delegated-to transport | Keep as the sole transport owner; no caller may bypass a T5 client for active T6-supported work. |
| Central policy | `internal/outbound` | injected `httpengine.Client` only | none owned | T5 | Validates T4 trust, T2, T3 audit, project/budget/expiry before delegation | Central | Keep; package remains I/O-free. |
| R15 crawl/discovery | `internal/assessmentbuiltin` | injected R3 client via `outbound.Client` | HTTP(S) read | R4/R11.2 owners | T1/T2/T3/T4 execution trust and R10.5 controls | Central | Keep as the supported active T6 dispatch path. |
| Assessment/campaign setup | `internal/cli/assessment.go`, `campaign.go` | R3 construction only | HTTP(S) | R13–R15 | Fresh T1/T2/T3/T4 task trust and append-only audit | Central | Keep as the approved R3 construction and T5 injection seam. |
| Standalone read CLIs | `internal/cli/http.go`, `crawl.go`, `content.go`, `vhost.go`, `validate.go`, `compare.go`, `fuzz.go`, and `discover TARGET` through `smart_discover.go` | direct `httpengine.NewEngine` and request dispatch | HTTP(S) | Legacy command paths | Older R1/R3 or R10.5-only checks; no T4/T5 operation | Legacy | Block active dispatch at the root CLI with a typed `legacy outbound blocked` error until each owner receives a separately reviewed T5 capability and trust context. |
| Legacy scan orchestration | `internal/cli/phase2_run.go` | direct R3 engine, provider calls, DNS enumeration, optional tools | HTTP(S), DNS, subprocess network activity | Legacy Phase 2/3/4 orchestration | `--authorized` and legacy R1/R3 only | None | Block at the root CLI as provider/legacy/subprocess outbound; do not silently run mixed central and non-central activity. |
| Credential auth test | `internal/cli/auth_test_command.go` | direct R3 `POST` with form body | HTTP(S) | R10 | Explicit attack gate and R1/R3 only; contains secret-bearing request body | Unsupported by read-only T5 | Block at the root CLI with a typed legacy-outbound error. It is not migrated into a GET/HEAD, secret-rejecting gateway capability. |
| In-memory R3 consumers | `crawler`, `probe`, `jsanalysis`, `contentdiscovery`, `fuzzing`, `injection`, `findingvalidation`, `smartdiscovery` | injected `httpengine.Client` | HTTP(S) | Existing module owner | Varies by owner; package does not construct a transport | Callable library seam | Retain as non-owning interfaces. T6 blocks their legacy CLI constructors; current supported R15 adapters wrap crawl/discovery through T5. |
| Provider HTTP | `internal/enum/sources.go` | `http.DefaultClient`, `http.NewRequestWithContext`, `x-apikey` | HTTPS | CRT.sh / VirusTotal sources | No T1–T5 path | None | Block through `scan`; no provider credential/header is propagated to T5's read-only target contract. |
| DNS enumeration | `internal/enum/dns.go` | `net.DefaultResolver.LookupHost` | DNS | Phase 2 enumerator | No T1–T5 path | None | Block through `scan`; do not add a second resolver or provider gateway. |
| Optional Nmap | `internal/portscan` via `internal/executil` | `executil.Run`, `os/exec` | subprocess/TCP | Optional tool wrapper | Same-scan target filtering only | Unsupported | Block through `scan`; retain parsing and argument validation as local code. |
| Optional Nuclei | `internal/vulncheck` via `internal/executil` | `executil.Run`, `os/exec` | subprocess/HTTP(S) | Optional tool wrapper | Same-scan target filtering only | Unsupported | Block through `scan`; retain parsing and fixed argument construction as local code. |
| Phase 1 local discovery | `internal/discovery`, `internal/probe/tcp.go` | ARP, local interface, bounded TCP dial | local L2/TCP | Phase 1 | Explicit local interface/CIDR authorization and limits | Not applicable | Keep as a documented local-only exception; it is not target-web egress and is not invoked by web commands. |
| URL/IP/header models | `policy`, `scope`, `evidence`, `validation`, `requestmutation`, `authsecurity`, and parser helpers | `net/url`, `net/http` types | none | Pure local packages | Input validation only | Not applicable | Keep; these imports do not dispatch outbound traffic. |
| Web fixture reader | `web/src/lib/fixtures.ts` | same-origin `fetch` of bundled fixture paths | local static asset retrieval | Static dashboard | No target semantics | Not applicable | Keep as local fixture acquisition; it has no configurable remote URL or scan endpoint. |
| Tests | `*_test.go` across packages | loopback clients, fake resolvers, R3 engines | test-only | Test suite | Deterministic test fixtures | Test-only | Permit only under test files; never treat fixtures as production exemptions. |

## Current T6 Supported Dispatch Set

The supported active target-web dispatch set is deliberately narrow: **R15 crawler read** and **R15 smart-discovery read** invoked by an assessment or campaign with a valid T1 record, T2 scope, T3 assurance, T4 context, T5 capability, budget binding, and audit event. All other legacy web, provider, DNS-enumeration, and subprocess command paths are routed to an explicit typed denial pending a separately scoped capability design.

This is a conservative compatibility change, not a claim that disabled legacy operations were previously T5-governed. Their former behavior is preserved in source and classified in this document rather than silently transformed.
