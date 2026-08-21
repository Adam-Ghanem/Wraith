# T6 Static Egress Audit

## Scope

The audit searched production and test source for direct standard-library HTTP, dialing, resolution, process execution, R3 construction, and frontend browser-network primitives. The full raw search evidence was retained during implementation review; this document records the security-relevant, manually classified outcome.

| Location group | Finding | Classification | Owner | T6 evidence and disposition |
|---|---|---|---|---|
| `internal/httpengine/*.go` | `net/http`, `net`, `net/url`, controlled resolver/dialer | Authorized transport implementation | R3 | The only package allowed to own target-web transport, resolution, and sockets. It maintains redirect and resolved-destination checks. |
| `internal/outbound/outbound.go` | injected R3 interface | Central policy-only gateway | T5 | No transport primitives; T5 validates before delegated R3 dispatch. CI rejects prohibited imports. |
| `internal/assessmentbuiltin/adapters.go` | injected R3 client wrapped by T5 | Central active adoption | R15 | Capability IDs bind crawl and discovery to per-request derived trust and audit. |
| `internal/cli/assessment.go` | `httpengine.NewEngine` | Approved construction seam | R13–R15 | Supplies the R3 engine only to a registry that has the T5 gateway and fresh T4 trust factory. |
| `internal/cli/{http,crawl,content,vhost,validate,compare,fuzz,smart_discover}.go` | `httpengine.NewEngine` | Legacy direct outbound | Legacy command owners | T6 root CLI denial prevents production dispatch, including reachable `discover TARGET` smart discovery, until reviewed migration. |
| `internal/cli/phase2_run.go` | R3 engine plus CRT/DNS/provider and Nmap/Nuclei calls | Mixed legacy/provider/subprocess outbound | Legacy scan | T6 root CLI denial prevents activation; source remains audited rather than removed. |
| `internal/cli/auth_test_command.go` | R3 `POST` with credential body | Unsupported credential-bearing outbound | R10 | T6 root CLI denial prevents activation; no credentials are sent through T5. |
| `internal/enum/sources.go` | `http.DefaultClient`, direct provider headers | Provider outbound bypass | Provider integration | Reachable only through blocked scan orchestration. |
| `internal/enum/dns.go` | `net.DefaultResolver` | DNS enumeration bypass | Phase 2 enumeration | Reachable only through blocked scan orchestration. |
| `internal/portscan`, `internal/vulncheck`, `internal/executil` | `os/exec` helper invocation | Subprocess network capability | Optional tool wrappers | Reachable only through blocked scan orchestration. |
| `internal/discovery`, `internal/probe/tcp.go` | ARP/local socket behavior | Local-only exception | Phase 1 | Separate Linux-first local network boundary; no target-web gateway claim. |
| `internal/*` parser/model packages importing `net/url` or `net/http` types | Parsing, headers, response inspection | Local-only implementation detail | Package owner | No request client, dialer, resolver, or subprocess call. |
| `web/src/lib/fixtures.ts` | fixture `fetch(path)` | Static same-origin fixture retrieval | Dashboard | No remote configuration, scanning target, or API call. |
| `*_test.go` | fake/loopback transport and test R3 construction | Test-only | Tests | Static enforcement excludes test files only where explicitly justified. |

## Enforcement Policy

T6 will add a deterministic source check that permits production R3 construction only in the audited assessment setup path and forbids new direct HTTP, resolver, socket, or subprocess primitives outside their explicitly documented owner packages. It will also check that legacy root command entry points return the typed T6 denial before they can reach their direct constructors.

The check is deliberately an ownership guard, not proof that source text alone provides authorization. Runtime proof remains T1, T2, T3, T4, T5, and R3 for the supported R15 operations.
