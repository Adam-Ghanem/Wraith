# Wraith

Wraith is a security research and defensive/offensive security tooling project. It is being built in deliberate phases with explicit safety boundaries.

## Status

Phase 1 is implemented as a Linux-first, local-network discovery tool. It is a standalone CLI for authorized local IPv4 inventory and is intentionally not an internet scanner, vulnerability scanner, exploitation framework, or web reconnaissance platform.

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

The current command deliberately has no arbitrary target flag, arbitrary port range, public-target mode, automatic subnet detection, external enrichment, scheduling, persistence, dashboard, OUI vendor lookup, TTL-based OS inference, Nmap integration, or Nuclei integration. Those are outside the frozen Phase 1 boundary.

## Safe testing

Use an isolated lab network, Linux network namespaces, disposable virtual machines, or devices that you own and are authorized to test. Begin with unit tests and interface inspection. Then verify ARP and TCP behavior against a small lab CIDR containing a known listener and a closed port. Confirm the selected interface and CIDR before each run, and stop if the result is incomplete or scope is ambiguous.

Do not use random public hosts, shared networks, employer networks, bug-bounty targets, or `scanme.nmap.org` for Phase 1. Public test hosts cannot override the local-only Phase 1 policy.

## Project documents

- [`docs/phase-1-scope.md`](docs/phase-1-scope.md) — frozen Phase 1 boundary and acceptance criteria.
- [`docs/responsible-use.md`](docs/responsible-use.md) — ownership, authorization, prohibited use, and operator duties.
- [`docs/project-plan.md`](docs/project-plan.md) — skill gaps, resources, AI-assistance guidance, Phase 1 build order, and future roadmap.
- [`docs/phase-1-prompt-reconciliation.md`](docs/phase-1-prompt-reconciliation.md) — reconciliation of the attached build prompt with the frozen Phase 1 boundary.
