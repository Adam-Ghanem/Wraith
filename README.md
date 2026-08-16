# Wraith

Wraith is a security research and defensive/offensive security tooling project. It is being built in deliberate phases with explicit safety boundaries.

## Status

Phase 1 is implemented as a Linux-first, local-network discovery tool. It is a standalone CLI for authorized local IPv4 inventory and is intentionally not an internet scanner, vulnerability scanner, exploitation framework, or web reconnaissance platform.

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

Phase 2 deliberately does not add content discovery, JavaScript analysis, port scanning of enumerated subdomains, Nmap/Nuclei wrappers, REST APIs, dashboards, PDF/CSV export, scheduling, or multi-tenancy.

## Safe testing

Use an isolated lab network, Linux network namespaces, disposable virtual machines, or devices that you own and are authorized to test. Begin with unit tests and interface inspection. Then verify ARP and TCP behavior against a small lab CIDR containing a known listener and a closed port. Confirm the selected interface and CIDR before each run, and stop if the result is incomplete or scope is ambiguous.

Do not use random public hosts, shared networks, employer networks, bug-bounty targets, or `scanme.nmap.org` for Phase 1. Public test hosts cannot override the local-only Phase 1 policy.

## Project documents

- [`docs/phase-1-scope.md`](docs/phase-1-scope.md) — frozen Phase 1 boundary and acceptance criteria.
- [`docs/responsible-use.md`](docs/responsible-use.md) — ownership, authorization, prohibited use, and operator duties.
- [`docs/project-plan.md`](docs/project-plan.md) — skill gaps, resources, AI-assistance guidance, Phase 1 build order, and future roadmap.
- [`docs/phase-1-prompt-reconciliation.md`](docs/phase-1-prompt-reconciliation.md) — reconciliation of the attached build prompt with the frozen Phase 1 boundary.
- [`docs/phase-2-implementation.md`](docs/phase-2-implementation.md) — Phase 2 architecture, migrations, limits, and authorized testing instructions.
