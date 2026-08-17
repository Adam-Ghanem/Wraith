# Wraith

Wraith is a security research and defensive/offensive security tooling project. It is being built in deliberate phases with explicit safety boundaries.

## Status

Phase 1 is implemented as a Linux-first, local-network discovery tool. It is a standalone CLI for authorized local IPv4 inventory and remains intentionally local-only; Phase 1 itself is not an internet scanner, vulnerability scanner, exploitation framework, or web reconnaissance platform. Phase 2 and Phase 3 add scoped, authorized web reconnaissance capabilities described below.

> **Legal Notice — `--authorized` is a self-attestation only.** This flag is a checkbox supplied by the operator, not technical verification. Wraith does not verify domain ownership, WHOIS records, or authorization in any way. You are 100% legally responsible for confirming real authorization—through ownership, written permission, or an in-scope bug bounty program—before running any scan against a target. Misuse against unauthorized targets may be illegal in your jurisdiction.

The current implementation provides the core contracts and pipeline for:

- Explicit local IPv4 interface and CIDR selection.
- Explicit operator confirmation that targets are owned or authorized.
- Bounded ARP candidate discovery on the selected local CIDR.
- TCP connect checks against the versioned curated top-100 TCP port list.
- Bounded, read-only service metadata capture.
- Machine-readable JSON and human-readable terminal output.
- Fail-closed validation for scope, authorization, limits, and port-list changes.

The Linux ARP adapter may require raw or packet-socket privileges. If packet access is denied, Wraith returns an operator-readable error that identifies the possible `CAP_NET_RAW`/`CAP_NET_ADMIN` or controlled elevated-execution requirement; it does not silently fall back to another scanner. Prefer the least-privilege capability or controlled elevated execution required by the host configuration. Do not run against a network you do not own or have explicit permission to test.

## Phase 2/3 Status

Phase 2 and Phase 3 provide a bounded web reconnaissance workflow for domains that the operator owns or is explicitly authorized to test. Every `scan` and `history` operation requires the `--authorized` self-attestation gate; Wraith does not technically verify ownership or permission. All network activity remains bounded by timeout, concurrency, rate, response-size, redirect, and persistence controls.

| Capability | Boundary |
| --- | --- |
| Subdomain enumeration | crt.sh passive certificate discovery, optional VirusTotal enrichment when `VT_API_KEY` is configured, and bounded DNS enumeration. |
| HTTP/HTTPS probing | Bounded requests with same-host redirect limits, response-size caps, technology guesses, and read-only metadata. |
| Content discovery | A curated path list with a random soft-404 baseline; findings are limited to meaningful 200, 301, 302, and baseline-different 403 observations. |
| JavaScript analysis | Same-host script extraction and bounded file analysis for API-like endpoints and redacted potential-secret pattern matches. |
| Storage and diffing | Versioned SQLite migrations, transactional scan persistence, and pure NEW/REMOVED/CHANGED history diffs. |
| Explicit exclusions | No subdomain port scanning, Nmap/Nuclei wrappers, vulnerability correlation, REST API, dashboard, PDF/CSV export, scheduling, or multi-tenancy. |

## Build and test

```bash
go test ./...
go build -o ./bin/wraith ./cmd/wraith
```

The repository is Linux-first. The ARP adapter uses the focused [`mdlayher/arp`](https://github.com/mdlayher/arp) package behind an internal interface. A typed Go adapter is preferred over shelling out to `arp-scan`: it avoids executable lookup and command parsing, keeps deadlines and scope checks inside the process, and makes permission failures explicit. The remaining scope and output logic is kept separate from packet access so it can be tested without network traffic.

## Usage

The command requires an explicit interface, canonical IPv4 CIDR, and authorization confirmation:

```bash
./bin/wraith discover \
  --interface eth0 \
  --cidr 192.168.1.0/24 \
  --authorized \
  --format terminal
```

For JSON output, either use `--format json` or the compatible `--json` alias:

```bash
./bin/wraith discover \
  --interface eth0 \
  --subnet 192.168.1.0/24 \
  --authorized \
  --json > result.json
```

Use `-v` for structured diagnostic messages on stderr. If the selected CIDR contains more than 256 candidate hosts, Wraith requires `--confirm-large-subnet` before discovery. The candidate count remains bounded by `--arp-max-targets`.

The Phase 1 `discover` command remains unchanged by default. Phase 2 adds opt-in persistence with `--save --db wraith.db`; it does not change the local-network scope or the Phase 1 scanning logic.

## Phase 2 web reconnaissance

Phase 2 operates only against a domain that you own or are explicitly authorized to test. The mandatory `--authorized` flag is a self-attestation checkbox, not technical verification: Wraith does not verify domain ownership, WHOIS records, or authorization in any way. You are 100% legally responsible for confirming real authorization through ownership, written permission, or an in-scope bug bounty program before running any scan against a target; misuse against unauthorized targets may be illegal in your jurisdiction. All external sources and HTTP probes are bounded with timeouts, concurrency limits, response-size limits, redirect limits, and DNS rate limits.

Run an authorized scan with terminal output:

```bash
./bin/wraith scan -d example.com --authorized --db wraith.db
```

Use JSON output when integrating the result into a local workflow:

```bash
./bin/wraith scan -d example.com --authorized --json --db wraith.db > scan.json
```

Compare the two most recent scans for the same domain:

```bash
./bin/wraith history -d example.com --authorized --db wraith.db
```

The default database is `wraith.db` in the current working directory. Inspect it with the SQLite CLI if installed, for example `sqlite3 wraith.db '.tables'` and `sqlite3 wraith.db 'SELECT id,target,scan_type,completed_at FROM scans ORDER BY id DESC;'`. Reset a local test database by stopping Wraith and removing only the explicitly selected database file, such as `rm -- wraith.db`; never delete a database unless you have confirmed its path and contents.

VirusTotal is optional and is used only when `VT_API_KEY` is present. If it is absent, Wraith logs that the optional source was skipped and continues with crt.sh and bounded DNS enumeration. A source failure does not abort the complete scan.

Phase 2 itself does not add port scanning of enumerated subdomains, REST APIs, dashboards, PDF/CSV export, scheduling, or multi-tenancy. Optional Nmap/Nuclei enrichment is documented separately as Phase 4 below.

## Phase 3 content discovery and JavaScript analysis

Phase 3 runs only as part of an authorized `wraith scan`. Content discovery tests a small curated list of high-value paths after recording a random-path soft-404 baseline; it reports only meaningful 200, 301, 302, or baseline-different 403 responses. JavaScript analysis parses script URLs from live HTML, resolves same-host relative references, fetches bounded files, extracts API-like endpoints, and identifies potential secret-shaped strings.

Both analyses run by default after Phase 2 HTTP probing. They can be disabled independently:

| Flag | Effect |
| --- | --- |
| `--skip-content-discovery` | Skip Phase 3 content discovery while retaining the rest of the authorized scan. |
| `--skip-js-analysis` | Skip Phase 3 JavaScript analysis while retaining the rest of the authorized scan. |

```bash
./bin/wraith scan -d example.com --authorized --db wraith.db --skip-content-discovery
./bin/wraith scan -d example.com --authorized --db wraith.db --skip-js-analysis
```

Secret findings are pattern matches only. They are always labeled `potential`, shown in redacted form, and never validated, used, or exfiltrated. A finding may be a false positive; operators must handle any suspected credential through an authorized incident-response process without giving Wraith the value.

## Phase 4 optional Nmap and Nuclei enrichment

Phase 4 adds two opt-in enrichment wrappers for an authorized `wraith scan`. Both flags are off by default and require the existing `--authorized` gate. Wraith passes only targets discovered and probed during the same scan; it does not accept arbitrary Nmap or Nuclei target injection.

```bash
./bin/wraith scan -d example.com --authorized --use-nmap --db wraith.db
./bin/wraith scan -d example.com --authorized --use-nuclei --json --db wraith.db > scan-with-vulns.json
./bin/wraith scan -d example.com --authorized --use-nmap --use-nuclei --db wraith.db
```

Nmap is invoked, when installed, with a conservative TCP-connect profile: `-sT -n -Pn -T3 --top-ports 1000 --max-retries 2 --open -oX -`. Wraith deliberately does not enable `-A`, OS detection, service-version detection, NSE scripts, UDP scanning, or aggressive timing. Each discovered IP target has a five-minute context timeout, and XML output is parsed directly with a bounded output limit.

Nuclei is invoked, when installed, against the live HTTP(S) hosts selected by Wraith’s same-scan web probing. The wrapper selects only the `cves,exposures,misconfiguration` template tags, applies a five-request-per-second built-in rate limit, emits JSONL without raw request/response bodies, disables redirects and interactsh, and blocks local/private network access. Fuzzing, DAST, code, headless, AI, and other intrusive modes are not enabled. Each scan has a ten-minute context timeout.

Nmap and Nuclei are optional external dependencies. If either binary is absent, the corresponding enrichment is skipped with a diagnostic message and the scan continues. Install Nmap from the [official Nmap downloads page](https://nmap.org/download.html). Install Nuclei by following the [official ProjectDiscovery installation guide](https://docs.projectdiscovery.io/opensource/nuclei/install). For example, a Go-based installation is available through the official Nuclei module:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Port findings record the observed source (`nmap` or `native`) and read-only service evidence. Nuclei findings preserve the severity reported by the selected template and include the template ID, matched URL, and description. Wraith reports these observations only; it never validates, exploits, follows up on, or invents severity for a vulnerability finding.

## Phase 5 static fixture dashboard

Phase 5 adds a local, read-only React dashboard under [`web/`](web/). It reads static `scan.json` and `history.json` fixtures only; it does not use a backend server, REST API, live SQLite connection, network polling, authentication, sessions, or write actions. The dashboard preserves the original evidence state: it displays per-row scan ID and observation time, source failures, explicit “none observed” text for empty finding types, and distinct `NEW`, `REMOVED`, and `CHANGED` history groups. It does not calculate risk scores, aggregate severity, or render scanner-derived values as HTML.

Generate fixtures using the existing authorized scan and history JSON paths:

```bash
./bin/wraith export-fixtures \
  -d example.com \
  --db wraith.db \
  --out web/public/fixtures \
  --authorized
```

The export writes `scan.json` first. If fewer than two completed scans exist, it leaves `scan.json` in place, does not retain `history.json`, prints an explanatory note to stderr, and returns the existing history error. After two scans, run the static dashboard locally:

```bash
cd web
pnpm install --frozen-lockfile
pnpm dev
```

The repository includes sanitized sample fixtures for local interface testing. Replace them only through the authorized export command or with your own appropriately redacted fixture copies. The browser UI is an evidence viewer, not a security assessment.

## Safe testing

Use an isolated lab network, Linux network namespaces, disposable virtual machines, or devices that you own and are authorized to test. Begin with unit tests and interface inspection. Then verify ARP and TCP behavior against a small lab CIDR containing a known listener and a closed port. Confirm the selected interface and CIDR before each run, and stop if the result is incomplete or scope is ambiguous.

Do not use random public hosts, shared networks, employer networks, bug-bounty targets, or `scanme.nmap.org` for Phase 1. Public test hosts cannot override the local-only Phase 1 policy.

## Project documents

- [`docs/phase-1-scope.md`](docs/phase-1-scope.md) — frozen Phase 1 boundary and acceptance criteria.
- [`docs/responsible-use.md`](docs/responsible-use.md) — ownership, authorization, prohibited use, and operator duties.
- [`docs/project-plan.md`](docs/project-plan.md) — skill gaps, resources, AI-assistance guidance, Phase 1 build order, and future roadmap.
- [`docs/phase-1-prompt-reconciliation.md`](docs/phase-1-prompt-reconciliation.md) — reconciliation of the attached build prompt with the frozen Phase 1 boundary.
- [`docs/phase-2-implementation.md`](docs/phase-2-implementation.md) — Phase 2 architecture, migrations, limits, and authorized testing instructions.
- [`docs/phase-2-premerge-review.md`](docs/phase-2-premerge-review.md) — Phase 2 pre-merge review findings, decisions, and verification notes.
- [`docs/phase-3-implementation.md`](docs/phase-3-implementation.md) — Phase 3 content-discovery and JavaScript-analysis boundaries, limits, and testing notes.
- [`docs/phase-2-3-real-target-verification.md`](docs/phase-2-3-real-target-verification.md) — Redacted record of the authorized Phase 2+3 live verification and its limitations.
- [`docs/phase-5-implementation.md`](docs/phase-5-implementation.md) — Static fixture dashboard, export command, hard exclusions, and Phase 5 testing limitations.
