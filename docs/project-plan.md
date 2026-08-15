# Wraith Project Plan

**Project:** Wraith

**Planning horizon:** Phase 1 through a functional open-source ASM platform

**Audience:** Solo developer with intermediate Go/Python capability and strong security fundamentals

**Author:** Manus AI

**Status:** Actionable baseline plan

## Scope decision before execution

The attached brief describes Wraith’s long-term vision as a web/network attack-surface-management platform that may eventually orchestrate tools such as Nmap and Nuclei. The previously frozen Wraith Phase 1 scope remains authoritative for the first implementation milestone: Linux-first local-network discovery on exactly one explicitly selected local IPv4 interface and CIDR; bounded ARP discovery; TCP connect checks against a curated top-100 TCP port list; bounded, read-only service metadata; JSON and terminal output; and owned or explicitly authorized targets only.

Accordingly, this plan treats public-target scanning, Nmap and Nuclei execution, web reconnaissance, vulnerability correlation, databases, dashboards, scheduling, and external APIs as **future-phase topics only**. It also treats OUI vendor enrichment, TTL-based operating-system heuristics, and any ping sweep beyond the bounded ARP boundary as deferred enhancements unless the Phase 1 scope contract is explicitly amended. This prevents the roadmap from silently expanding the phase that has already been frozen.

> **Operating rule:** If a feature increases the target boundary, adds a protocol or probing method, contacts an external service, persists findings, runs unattended, or makes a security conclusion, it is not a Phase 1 implementation detail. It is a separately reviewed scope change.

---

# 1. Skill Gap Analysis

## 1.1 Existing strengths that map directly to Wraith

The developer already has a useful foundation. Linux and networking fundamentals map to interface selection, IPv4/CIDR reasoning, ARP behavior, TCP connection semantics, timeouts, and packet-level troubleshooting. SOC experience with Wazuh and Suricata maps to event interpretation, defensive observability, false-positive awareness, and the discipline of treating tool output as evidence rather than certainty. Existing Python security-tooling experience transfers to CLI ergonomics, parsers, fixtures, automation, and test harnesses. FastAPI and React experience will be valuable later, but deliberately should not pull the first phase toward a dashboard or API.

The principal execution advantage is security judgment. The main risk is not lack of intelligence or motivation; it is allowing an exciting ASM vision to become too broad for one developer. The project should therefore use a “thin vertical slice first” strategy: one local discovery command, deterministic bounded behavior, test fixtures, safe output, and a release-quality README before any remote or web capability is added.

## 1.2 Skill gaps and the fastest way to close them

| Phase or concern | Skill to strengthen | Why it matters | Fastest realistic path |
| --- | --- | --- | --- |
| Phase 1 | Go module and package design | The project needs clear boundaries between scope validation, discovery, probing, metadata, and output. | Read the official Go package tutorial, then create a 30-minute toy module with `cmd/`, `internal/`, interfaces, and table-driven tests. Learn by keeping the first production package small. |
| Phase 1 | Go concurrency with cancellation | A worker pool must bound concurrent TCP connects, honor timeouts, stop cleanly, and avoid goroutine leaks. | Read Go’s `context` and pipeline guidance, then build a practice worker pool that processes 100 integers, supports cancellation, and proves all workers exit in a test. Do not begin with network sockets. |
| Phase 1 | `net`, `netip`, deadlines, and connection errors | TCP connect results must distinguish open, refused, timeout, filtered/unreachable, and local errors without overclaiming. | Write a local-only socket exercise using loopback listeners and deliberately closed ports. Test `context` cancellation and `SetDeadline` behavior before using real LAN targets. |
| Phase 1 | Linux interface and privilege model | ARP and packet access are platform-specific. Linux capabilities distinguish targeted privileges from unrestricted root access; `CAP_NET_RAW` covers raw and packet sockets.[8] | Read `capabilities(7)`, inspect `ip addr` and `ip route`, and build a read-only interface-inspection command. Prefer least privilege and document when a capability or elevated privilege is unavoidable. |
| Phase 1 | ARP frame handling | ARP is link-local and easy to get wrong around interface choice, broadcast behavior, retries, and response matching. | Read RFC 826 conceptually and the `mdlayher/arp` examples. Build a lab-only ARP request/response fixture or network namespace test. Keep packet construction behind a narrow interface so it can be tested without raw traffic. |
| Phase 1 | Resource bounding | Discovery tools can accidentally become noisy through unbounded targets, retries, ports, response sizes, or runtime. | Write a limits table before implementation. Add tests that fail closed when a limit is missing or exceeded. Review every loop for a deadline, cancellation path, and maximum work item count. |
| Phase 1 | Defensive parsing of service metadata | Banners and protocol responses are untrusted, may be malformed, and may contain secrets or control characters. | Create fixed response fixtures containing oversized, malformed, binary, and instruction-like text. Implement length limits, redaction rules, and safe terminal rendering before connecting to actual services. |
| Phase 1 | Deterministic JSON schema design | The output is the first public contract and must support later diffing without becoming a database prematurely. | Design 5–10 representative JSON fixtures by hand. Write schema-level tests for stable field names, explicit unknown values, errors, timestamps, scope version, and port-list version. |
| Phase 1 | CLI design and exit semantics | A standalone `wraith discover` command must be usable in scripts and understandable interactively. | Use Cobra only for command wiring; keep behavior in internal packages. Define exit codes for invalid scope, authorization failure, partial run, and successful run before writing flags. |
| Phase 1 | Test doubles for network code | Reliance on a real LAN makes tests flaky and tempts unsafe experimentation. | Define interfaces for ARP discovery, TCP dialing, and metadata reads. Unit-test them with fakes; reserve a small number of integration tests for a disposable lab namespace. |
| Phase 2 | DNS and HTTP fundamentals | Web reconnaissance requires precise handling of DNS records, redirects, TLS, virtual hosts, and content types. | Build a small authorized-only DNS/HTTP inventory tool against a domain you own. Study Go’s `net/http`, `crypto/tls`, and resolver behavior while writing negative tests for redirects and private-address confusion. |
| Phase 2 | SSRF and web crawler safety | A web recon feature can accidentally reach internal services or follow attacker-controlled redirects. | Threat-model every fetch boundary. Implement allowlists, private/reserved-address rejection, redirect policy, response-size caps, and per-host rate limits before adding discovery features. |
| Phase 3 | Data normalization and correlation | Matching banners, technologies, templates, and CVEs requires confidence levels and provenance rather than string concatenation. | Start with a hand-built corpus of 20 observations and 20 expected normalized records. Require each correlation to retain source, timestamp, rule version, and confidence. |
| Phase 3 | Vulnerability-scanner integration | Nuclei is a template-driven vulnerability scanner, not a harmless metadata library; its templates can exercise multiple protocols.[7] | Read the official project and template documentation, run only against an isolated lab, and first build an adapter that accepts fixtures rather than invoking the scanner. Manual review is mandatory before any live integration. |
| Phase 4 | SQLite schema and migrations | Persistence introduces lifecycle, integrity, privacy, and migration concerns. | Read SQLite’s transaction and locking documentation, then model assets, observations, runs, and diffs in a throwaway database. Add migration tests before connecting it to the application. |
| Phase 4 | API authorization and secure storage | A dashboard turns local tool output into a multi-user attack surface. | Implement authentication and object-level authorization in a toy FastAPI service first. Apply input validation, parameterized queries, safe error handling, security headers, and secret hygiene from the beginning. |
| Phase 5 | React data presentation | A dashboard must make uncertainty and provenance visible rather than turning observations into false certainty. | Build a static React view from JSON fixtures before adding a backend. Include empty, partial, stale, and error states. Do not render banners as HTML. |
| Phase 5 | Diffing and reporting | Time-based change detection is a core value-add and needs stable identity, normalization, and explainable output. | Implement a pure function that compares two fixture snapshots. Add tests for additions, removals, changes, unknowns, and reordered input before introducing storage or UI. |
| All phases | Release engineering and dependency hygiene | An open-source security tool needs reproducible builds and controlled dependencies. | Add `go test ./...`, `go vet`, a formatter, a linter, dependency review, and a minimal CI workflow before Phase 1 is declared complete. Pin versions and review license compatibility. |
| All phases | Scope and authorization discipline | The highest-risk failure is scanning the wrong network or presenting an incomplete result as a security conclusion. | Keep `docs/phase-1-scope.md` and `docs/responsible-use.md` in the repository. Make scope validation and authorization confirmation acceptance criteria, not afterthoughts. |

## 1.3 Learning cadence for a solo developer

Use a 70/20/10 split. Approximately 70 percent of time should be spent building and testing the current slice, 20 percent reading primary documentation and reviewing packet traces or fixtures, and 10 percent writing notes, updating the threat model, and pruning scope. Avoid multi-week study periods before producing a working artifact; each learning block should end with a small test, fixture, or documented decision.

The developer should maintain a short decision log. Each entry should state the problem, the selected approach, the rejected alternatives, the security consequence, and the test that proves the decision. This is especially valuable for ARP implementation, privilege handling, output schema, and any future external integration.

---

# 2. Resource List

## 2.1 Phase 1 Go libraries and packages

The default should be the Go standard library plus the smallest number of focused dependencies. Avoid a framework-heavy design in the first phase.

| Resource | Role | Recommendation and justification |
| --- | --- | --- |
| `context`, `net`, `net/netip`, `net/http`, `encoding/json`, `text/tabwriter`, `sync`, `time` | Core behavior | Use the standard library for cancellation, IPv4/CIDR validation, TCP dialing, bounded reads, JSON, terminal tables, worker coordination, and deadlines. Fewer dependencies make the first security boundary easier to review. |
| `github.com/mdlayher/arp` | ARP packet construction and parsing | Strong candidate for a narrow Linux ARP adapter. The repository describes itself as an RFC 826 ARP implementation and is MIT licensed.[3] Keep it behind an interface and test the adapter separately from scope validation. |
| `github.com/vishvananda/netlink` | Linux interface/address/neighbor inspection | Useful for mapping the operator-selected interface to its IPv4 address and CIDR and for read-only Linux network state. Its package documentation describes Linux netlink access and notes that netlink communication commonly requires elevated privileges.[2] Do not use its mutation APIs. |
| `github.com/google/gopacket` and `github.com/google/gopacket/pcap` | Optional packet decoding/capture | Consider only if the ARP adapter needs packet capture or detailed decoding. The pcap package is libpcap-backed and supports live capture, filters, and packet reads.[1] It adds a system dependency and a larger review surface, so it should not be a default dependency if `mdlayher/arp` is sufficient. |
| `github.com/spf13/cobra` | CLI command wiring | Suitable for `wraith discover` and future subcommands. Its repository describes it as a modern Go CLI command framework and is Apache-2.0 licensed.[4] Keep business logic outside Cobra callbacks. |
| `github.com/rs/zerolog` or `go.uber.org/zap` | Optional structured diagnostics | Prefer the standard library’s `log/slog` if the selected Go version supports the needed behavior. Add a third-party logger only when structured diagnostics materially improve the CLI. Never log credentials, raw sensitive banners, or authorization documents. |
| `golangci-lint` | Static analysis | Use as a development tool in CI, not a runtime dependency. Require that the chosen configuration is small enough for the solo developer to understand. |

A practical Phase 1 dependency decision is: standard library, `mdlayher/arp`, `vishvananda/netlink`, and Cobra. Add gopacket only after a concrete packet-decoding test demonstrates the need. All dependencies must be pinned through `go.mod` and reviewed for license, maintenance, transitive dependencies, and install behavior.

## 2.2 Linux permissions and system dependencies

Start with an unprivileged interface-inspection mode. The ARP adapter may require raw or packet-socket access depending on the implementation. Linux documents `CAP_NET_RAW` as the capability that permits RAW and PACKET sockets.[8] Do not assume that running the entire program as root is the only solution; prefer a narrow capability or a clearly documented elevated test command, and drop privileges after opening a required resource if the design permits it.

The README should state the exact system packages needed for the selected adapter. If gopacket/pcap is used, libpcap development and runtime packages must be documented. The program must detect insufficient privilege and emit a clear error rather than retrying, changing the selected interface, or silently falling back to broader behavior.

## 2.3 Future external tools and APIs

These resources belong to later phases and must not be called by Phase 1.

| Resource | Future role | Current planning constraint and known limit |
| --- | --- | --- |
| crt.sh | Certificate-transparency discovery for domains explicitly owned or authorized by the operator | A crt.sh maintainer post documented throttling at 60 requests per IP per minute with a burst of 5.[5] Treat this as historical operational guidance, not a guaranteed contract. Use caching, a conservative client rate, backoff, and no scheduled polling by default. |
| VirusTotal Public API | Optional enrichment for authorized assets in a later phase | The official documentation states 500 requests/day and 4 requests/minute, and prohibits use of the Public API in commercial products or services.[6] Do not design around this tier without a licensing/product decision. Never upload private data or samples without explicit authorization. |
| Shodan API | Optional third-party context for public-facing assets in a later, separately authorized phase | Shodan’s official requirements page says an API key is required and can be obtained with a free account, but does not state a universal free-tier query quota on that page.[9] Verify current pricing, query credits, scan permissions, and terms before implementation; do not assume a free key permits bulk use. |
| NVD API | Future CVE/CPE enrichment and correlation | NVD documents 5 requests per rolling 30 seconds without a key and 50 with a key.[10] Prefer scheduled bulk feeds or cached local data in a future phase rather than per-observation lookups. Any correlation must preserve source and timestamp. |
| Nmap | Optional later comparison or integration | Nmap is not permitted in Phase 1. If a later phase uses the public `scanme.nmap.org` host, Nmap’s official guidance says that permission covers Nmap scanning only, excludes exploit and denial-of-service testing, and asks for no more than a dozen scans per day.[11] Prefer owned lab targets anyway. |
| Nuclei | Future authorized vulnerability checks | Nuclei is a YAML-template-driven vulnerability scanner supporting multiple protocols.[7] Treat it as an active security-testing integration with explicit target authorization, template review, rate controls, dry runs, and human approval. |

## 2.4 Datasets and safe sourcing

The curated top-100 TCP list should be a project-owned, reviewed asset committed to the repository, with a version, rationale, and change history. It may be informed by public service/port registries such as IANA’s Service Name and Transport Protocol Port Number Registry, but the Phase 1 runtime must not fetch a remote list or accept an arbitrary port range. Duplicate, privileged, unusual, and high-impact ports should be intentionally reviewed rather than copied blindly.

An OUI vendor database is not required by the frozen Phase 1 acceptance criteria. If a later scope decision adds vendor enrichment, use an official IEEE registration source or a legally redistributable snapshot, pin the snapshot date, document license and update process, and perform lookup locally. Do not query an external vendor service at runtime in Phase 1. The same rule applies to service-fingerprint databases: prefer a small reviewed local mapping over a live external lookup.

No wordlist is needed for Phase 1. Wordlists become relevant only to later web-content discovery, where each list must have a documented license, a narrowly authorized target scope, a maximum request budget, and a reason for inclusion.

## 2.5 Legal and safe test targets

The default test target is an isolated lab network that the developer owns. Good fixtures include two Linux virtual machines, a disposable container network, or Linux network namespaces connected through a veth pair. The test environment should include one known listener, one closed port, one deliberately filtered or delayed service, and one malformed metadata responder. Capture traffic in the lab to verify that only the selected CIDR and curated ports are touched.

The developer’s own home-lab devices are acceptable only when the developer owns or has explicit permission to test them and understands the operational impact. A test domain is acceptable only when its registrant or operator has explicitly authorized the planned activity. `scanme.nmap.org` is not a Phase 1 target because Phase 1 is local-network-only; its later use is governed by the Nmap-specific restrictions above.[11]

Do not use random public hosts, cloud providers, university networks, employer networks, shared Wi-Fi, bug-bounty targets, or “interesting” domains as test targets without target-specific written authorization. A DNS record or HTTP response is not proof of permission.

---

# 3. AI Assistance Plan

AI assistance should accelerate scaffolding and review while leaving the developer responsible for understanding every network, authorization, parsing, and security decision. The developer should ask an assistant for small, reviewable changes with tests, not for a complete scanner generated from a single prompt.

| Phase | AI is genuinely useful for | Developer must write, understand, and manually review |
| --- | --- | --- |
| Phase 1 | Go module scaffolding, README structure, Cobra command boilerplate, JSON fixture generation, table formatting, test case matrices, error-message wording, and documentation cleanup. | Scope validation, CIDR containment, interface-to-CIDR mapping, ARP framing, raw/packet socket handling, worker-pool cancellation, deadlines, metadata parsing, output redaction, and all code that causes network traffic. Blindly accepting generated packet or concurrency code is unsafe. |
| Phase 2 | Parser scaffolding, DNS record models, HTTP fixture generation, normalization helpers, and test-data expansion. | SSRF defenses, redirect policy, DNS rebinding resistance, private/reserved-address checks, request budgets, content discovery behavior, and any code that fetches an operator-influenced URL. The developer must manually inspect every outbound request path. |
| Phase 3 | Adapter boilerplate, schema mapping, report templates, fixture conversion, and correlation test-case generation. | Nuclei invocation policy, template allowlisting, command execution, output validation, provenance, confidence scoring, false-positive handling, and CVE/CPE correlation logic. Model output and scanner output are untrusted data. |
| Phase 4 | CRUD scaffolding, migration skeletons, API documentation, and UI fixture wiring. | Database schema invariants, authorization checks, tenant/object ownership, secrets handling, migration safety, audit logging, rate limits, and all server-side URL or command execution. Use threat modeling before accepting generated endpoints. |
| Phase 5 | React component scaffolding, table and filter layouts, report prose drafts, CI YAML drafts, and release-note structure. | Interpretation of uncertainty, diff semantics, data retention, security headers, access control, packaging, dependency review, and claims made in reports. Never let AI turn “not observed” into “not present.” |

The assistant must not receive API keys, credentials, private authorization letters, unredacted sensitive banners, personal data, or the full contents of a customer network inventory. The developer should give it synthetic fixtures whenever possible. Any generated shell command must be read before execution, especially commands involving raw sockets, package installation, capabilities, firewall rules, or target lists.

A safe AI workflow is: describe the narrow task; require tests and an explanation; inspect the diff; run formatting and static checks; run unit tests with no network access; run integration tests only in the isolated lab; then manually review the trust boundaries. Network-connected tests should never be introduced solely because an assistant suggested them.

---

# 4. Phased Roadmap — Start With This First Phase

## Phase 1: Local Network Discovery Module

### 4.1 Phase 1 objective and acceptance boundary

The Phase 1 deliverable is a standalone Linux-first CLI command, `wraith discover`, that performs a bounded inventory run on one explicitly selected local IPv4 interface and CIDR. It may discover local IPv4 neighbors using bounded ARP, attempt TCP connections against the curated top-100 TCP port list with a bounded concurrent worker pool, collect limited read-only service metadata, and emit equivalent JSON and terminal output.

The phase does not include public-target scanning, arbitrary target lists, arbitrary port ranges, UDP or IPv6 scanning, exploitation, credential testing, Nmap, Nuclei, web reconnaissance, vulnerability correlation, database persistence, dashboards, scheduling, external APIs, or remote enrichment. It also does not promise complete OS fingerprinting, CVE detection, or security conclusions. If MAC addresses are exposed as a direct ARP observation, they may be represented as raw observed link-layer metadata; vendor lookup and TTL-based OS heuristics are deferred until separately approved because they introduce additional datasets and inference claims.

The success criterion is not “it scanned a large network.” It is “it performs the smallest authorized local inventory reliably, fails closed on ambiguity, is understandable from its output, and has tests that prove it did not exceed its boundary.”

### 4.2 Exact folder and package structure

The repository is currently empty, so create the following structure as the first project skeleton. The structure intentionally keeps packet access, policy, and output separate.

```text
Wraith/
├── cmd/
│   └── wraith/
│       └── main.go
├── internal/
│   ├── authorization/
│   │   ├── policy.go
│   │   └── policy_test.go
│   ├── cli/
│   │   ├── discover.go
│   │   └── discover_test.go
│   ├── config/
│   │   ├── scope.go
│   │   ├── limits.go
│   │   └── config_test.go
│   ├── discovery/
│   │   ├── arp.go
│   │   ├── arp_linux.go
│   │   ├── arp_stub.go
│   │   ├── interface.go
│   │   └── discovery_test.go
│   ├── metadata/
│   │   ├── reader.go
│   │   ├── banner.go
│   │   └── reader_test.go
│   ├── model/
│   │   ├── result.go
│   │   └── result_test.go
│   ├── ports/
│   │   ├── top100.go
│   │   └── top100_test.go
│   ├── probe/
│   │   ├── tcp.go
│   │   ├── worker_pool.go
│   │   └── tcp_test.go
│   ├── output/
│   │   ├── json.go
│   │   ├── terminal.go
│   │   └── output_test.go
│   └── testutil/
│       ├── fakes.go
│       └── fixtures.go
├── testdata/
│   ├── metadata/
│   │   ├── banner_http.txt
│   │   ├── banner_ssh.txt
│   │   ├── malformed.bin
│   │   └── oversized.txt
│   ├── results/
│   │   ├── complete.json
│   │   └── partial.json
│   └── scope/
│       ├── valid.json
│       └── invalid.json
├── docs/
│   ├── phase-1-scope.md
│   ├── responsible-use.md
│   └── project-plan.md
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── LICENSE
└── .github/
    └── workflows/
        └── ci.yml
```

The `internal` directory prevents accidental reuse as a public library before the interfaces stabilize. The Linux-specific ARP implementation should be isolated behind build tags or a narrow adapter so unit tests can run without raw-socket privileges. The `model` package should contain data types only; it must not perform network activity. The `config` package must validate scope before any discovery or probe object is constructed.

### 4.3 Recommended Phase 1 result model

Use a versioned result envelope. A minimal conceptual shape is:

```json
{
  "schema_version": "phase1.v1",
  "scope": {
    "interface": "eth0",
    "cidr": "192.0.2.0/24",
    "authorization_confirmed": true
  },
  "port_list": {
    "name": "curated-top100-tcp",
    "version": "2026-08-14"
  },
  "run": {
    "started_at": "2026-08-14T12:00:00Z",
    "completed_at": "2026-08-14T12:00:08Z",
    "status": "complete"
  },
  "targets": [],
  "limitations": [],
  "errors": []
}
```

The example is a schema illustration, not scanning code or a promise that documentation dates should be used at runtime. A target record should distinguish address, optional observed MAC, discovery state, per-port TCP result, bounded metadata, and explicit unknown/error values. Do not overload `null`, empty string, and “closed” to mean the same thing. Terminal output should show the selected scope first, then a compact device/port table, then warnings and limitations.

### 4.4 Step-by-step build order

| Order | Build and test | Definition of done |
| --- | --- | --- |
| 1 | Repository hygiene and documentation | `go.mod`, README, license, CI skeleton, scope documents, and a no-network unit-test command exist. |
| 2 | Scope types and validation | Interface name, IPv4 address, CIDR, limits, authorization confirmation, and port-list version are validated before any network object is opened. Invalid and ambiguous inputs fail closed. |
| 3 | Curated top-100 asset | The list is committed, reviewed, deduplicated, transport-labeled, versioned, and tested for exact count and valid TCP port values. There is no arbitrary range flag. |
| 4 | Pure result model and JSON output | Fixtures round-trip through JSON. Schema version, scope, status, errors, limitations, and unknown values are stable. JSON output performs no network activity. |
| 5 | Terminal output | `text/tabwriter` renders deterministic tables, escapes control characters, and clearly displays scope and partial-result status. |
| 6 | Interface inspection | A read-only adapter lists the selected local interface and associated IPv4 CIDR. Unit tests cover down interfaces, no IPv4 address, multiple addresses, mismatched CIDR, and non-local candidates. |
| 7 | TCP dialer abstraction | A fake dialer proves open, refused, timeout, filtered/unreachable, cancellation, and local-error mapping. Every attempt has a deadline and the target must be within the selected CIDR. |
| 8 | Worker pool | Build a bounded goroutine pool with `context` cancellation, a finite job queue, a maximum concurrency, and a total deadline. Tests prove no goroutine leak and no work after cancellation. |
| 9 | Read-only metadata adapter | Start with bounded banner reads for a small protocol allowlist or conservative port-based guess. Cap bytes and time, reject credential prompts and state-changing paths, and test malformed/oversized/control-character responses. |
| 10 | ARP adapter in an isolated Linux lab | Use `mdlayher/arp` or the selected alternative behind an interface. Send only within the selected CIDR, match responses to the request, bound retries and duration, and test with network namespaces or owned devices. |
| 11 | Pipeline composition | Run validation → bounded ARP → target normalization → bounded TCP worker pool → bounded metadata → output. No stage may expand scope or contact an external service. |
| 12 | Integration and negative tests | Verify traffic and results in an isolated lab. Include public-target input, mismatched CIDR, missing authorization, invalid port list, privilege failure, timeout, malformed metadata, output failure, and cancellation cases. |
| 13 | Release gate | Run formatter, `go test ./...`, race detector where practical, `go vet`, linter, dependency review, documentation review, and a manual diff of the network-bound code. |

Do not add vendor lookup, TTL analysis, OS guessing, Nmap, Nuclei, web requests, or a database merely because the initial pipeline works. Each would need a written scope decision and new tests.

### 4.5 Safe local-network testing procedure

First create or select an isolated network that the developer owns. Record the interface name, IPv4 CIDR, authorization basis, and the test window. Start with interface inspection and JSON serialization; these stages should be testable without sending packets. Run against a small lab CIDR rather than the entire home network until the traffic pattern is understood.

Next run ARP discovery with the smallest permitted concurrency and retry budget. Confirm with a packet capture or the lab router that only ARP traffic for the selected local CIDR is emitted. Then enable TCP checks against a lab listener and a deliberately closed port. Confirm that the destination set is exactly the intended addresses and that the port set is exactly the committed top-100 list.

Finally test service metadata using a local fixture server that returns a short banner, a long banner, malformed bytes, and a credential-like prompt. The correct behavior is bounded capture, safe display, and no attempt to authenticate or proceed beyond the permitted metadata interaction. Test cancellation by stopping the run mid-operation and verify that workers terminate and no new connection attempts begin.

Do not use `scanme.nmap.org`, random internet hosts, employer networks, shared Wi-Fi, bug-bounty targets, or public cloud ranges for Phase 1. The Phase 1 policy requires owned or explicitly authorized local targets. A public test host may be suitable for a later, separately authorized tool-specific experiment, but it cannot override the frozen boundary.

### 4.6 Phase 1 time estimate

For an intermediate developer working part time, estimate **30–45 focused hours**, or approximately **2–3 weeks at 15 hours per week**. A realistic schedule is shown below.

| Workstream | Estimate |
| --- | ---: |
| Repository, scope validation, result model, and JSON/terminal output | 6–8 hours |
| TCP dialer, bounded worker pool, and unit tests | 6–8 hours |
| Read-only metadata adapter and defensive parsing tests | 4–6 hours |
| Linux interface mapping and ARP adapter | 8–12 hours |
| Isolated-lab integration tests and traffic verification | 4–6 hours |
| CI, README, dependency review, and cleanup | 2–5 hours |
| **Total** | **30–45 hours** |

Add a 25 percent contingency if Linux raw-socket behavior, virtual networking, or privilege configuration is new. The phase should be considered complete only when the tests and documentation are complete, not when the first successful LAN result appears.

### 4.7 Phase 1 scope-creep gates

The following requests require a pause and written review: arbitrary ports; UDP or IPv6; public or routed targets; Nmap or Nuclei; web requests; OUI downloads; live vendor or CVE APIs; TTL-based OS claims; password or credential checks; persistence; scheduling; a dashboard; or any “temporary” bypass for an integration test. The correct response to a blocked or ambiguous test is to improve the lab fixture or the error path, not to broaden the target.

---

# 5. Full Roadmap Outline

The following phases are intentionally brief. Each should receive its own detailed scope, threat model, authorization policy, acceptance tests, and time estimate before implementation begins.

## Phase 2: Authorized web and domain reconnaissance

Add a separate, explicitly authorized target model for domains and web assets. Cover passive certificate-transparency and DNS enumeration, subdomain normalization, HTTP/TLS probing, redirect handling, content discovery, and JavaScript asset analysis. Build SSRF defenses, private-address rejection, per-host rate limits, response-size caps, redirect policy, provenance, and an operator-visible authorization record before adding breadth. External APIs remain optional and must not be assumed to be free or commercially usable.

**Scope-creep warning:** Phase 2 can easily become an internet crawler. Start with owned domains, passive sources, a small explicit path set, and a strict request budget. Do not make “all subdomains” or “all URLs” the definition of done.

## Phase 3: Vulnerability correlation and controlled Nuclei integration

Normalize observations from Phase 1 and Phase 2, then add rule-based correlation with confidence and provenance. Integrate Nuclei only after the adapter can operate on fixtures and after the operator can select an allowlisted template set, target scope, rate limit, and approval state. Add NVD/CPE enrichment only through cached, rate-limited, source-traceable data.

**Scope-creep warning:** Correlation is not proof of vulnerability. Keep “observed,” “matched,” “suspected,” and “confirmed by authorized test” as separate states. Do not turn a banner string into an exploit claim.

## Phase 4: Persistence, API, and authorization model

Introduce SQLite or another deliberately selected store for assets, runs, observations, normalized findings, provenance, and diffs. Add migrations, retention rules, backups, structured audit events, authentication, object-level authorization, input validation, rate limiting, safe errors, and secret handling. External integrations should be explicit adapters with disabled-by-default configuration.

**Scope-creep warning:** Do not build a multi-tenant SaaS architecture before one-user local persistence is correct. The first persistent release should make deletion, export, and data ownership easy.

## Phase 5: Dashboard, diffing, and reporting

Build a local or authenticated dashboard over stable JSON/API contracts. Add snapshot comparison, change timelines, asset grouping, evidence links, confidence labels, limitations, and exportable reports. The UI must preserve uncertainty and must not render untrusted banners or scanner output as HTML.

**Scope-creep warning:** Avoid charts that imply risk scores before the underlying evidence model is stable. A clean interface is valuable only when it makes provenance and incompleteness visible.

## Phase 6: Hardening, CI, packaging, and documentation

Add reproducible builds, signed or checksummed release artifacts, dependency and license review, static analysis, race testing where practical, isolated integration tests, threat-model updates, operator documentation, example lab fixtures, and a responsible disclosure process. Publish a clear support matrix for Linux distributions and privilege requirements.

**Scope-creep warning:** Do not add more scanners to compensate for missing reliability. A small, tested, explainable tool is a stronger flagship portfolio project than a broad orchestrator that cannot prove its boundaries.

## Delivery milestones

| Milestone | Required outcome |
| --- | --- |
| M0 | Repository skeleton, scope policy, responsible-use policy, threat model, and CI baseline. |
| M1 | Phase 1 pure core: scope validation, port list, result schema, JSON, terminal table, and fake-driven tests. |
| M2 | Phase 1 Linux integration: bounded ARP, TCP connect worker pool, read-only metadata, and isolated-lab verification. |
| M3 | Phase 1 release: README, limitations, authorization checklist, reproducible build, and no-scope-creep review. |
| M4 | Phase 2 design review: separate domain/web scope and SSRF threat model, with no implementation commitment until approved. |
| M5 | Phase 3–6 design reviews: each future capability receives its own authorization, data, privacy, and operational controls. |

## Final project rule

Wraith should earn complexity. Every new capability must first demonstrate a user need, an explicit authorization model, a bounded implementation, a testable failure mode, and a clear explanation of what the output does **not** prove. This rule is more important than the choice of framework or scanner.

---

## References

[1]: https://pkg.go.dev/github.com/google/gopacket/pcap "Go Packages: github.com/google/gopacket/pcap"

[2]: https://pkg.go.dev/github.com/vishvananda/netlink "Go Packages: github.com/vishvananda/netlink"

[3]: https://github.com/mdlayher/arp "GitHub: mdlayher/arp"

[4]: https://github.com/spf13/cobra "GitHub: spf13/cobra"

[5]: https://groups.google.com/g/crtsh/c/NZJntKrBdmg "crt.sh maintainer discussion: Rate limits for crt.sh"

[6]: https://docs.virustotal.com/reference/public-vs-premium-api "VirusTotal API: Public vs Premium API"

[7]: https://github.com/projectdiscovery/nuclei "GitHub: projectdiscovery/nuclei"

[8]: https://man7.org/linux/man-pages/man7/capabilities.7.html "Linux capabilities(7) manual page"

[9]: https://developer.shodan.io/api/requirements "Shodan Developer API: Requirements"

[10]: https://nvd.nist.gov/developers/start-here "NIST NVD Developers: Start Here"

[11]: https://nmap.org/book/legal-issues.html "Nmap Network Scanning: Legal Issues"
