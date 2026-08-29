# Wraith

<p align="center">
  <img src="docs/assets/wraith-logo.png" alt="Wraith raven-feather logo" width="320">
</p>

<p align="center">
  <strong>Safety-first attack-surface discovery & evidence review in Go.</strong><br>
  Bounded collection · Explicit authorization · Local evidence · Fail-closed behavior
</p>

[![CI](https://github.com/Adam-Ghanem/Wraith/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Adam-Ghanem/Wraith/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Wraith is a phased Go toolkit for **authorized** local-network discovery, web reconnaissance, evidence collection, reporting, regression review, and security governance. It is designed to make scope, limits, provenance, and exclusions explicit rather than pretending that scanner output is a security verdict.

> **Authorization:** `--authorized` is an operator self-attestation, not technical verification. Only scan systems you own or are explicitly authorized to test.

## Product preview

![Wraith Evidence workspace product showcase](docs/assets/wraith-evidence-showcase.png)

## Evidence dashboard

![Wraith Evidence Ledger rendering the bundled fixture-backed snapshot evidence](docs/assets/wraith-dashboard-sample.webp)

The dashboard is a static, read-only viewer backed by sanitized local fixtures. It does not perform scanning or make network requests.

## What Wraith covers

| Area | Highlights |
|---|---|
| **Discovery** | Linux-first local IPv4 discovery, bounded ARP candidates, curated TCP checks, service metadata |
| **Web recon** | Authorized domain discovery, HTTP probing, content discovery, JavaScript analysis, persistence and diffs |
| **Enrichment** | Optional Nmap/Nuclei wrappers with the same-scan target boundary |
| **Evidence** | Local SQLite evidence, redaction, provenance, correlation, snapshots and regression comparison |
| **Assessment** | Bounded parameter testing, passive checks, controlled reproduction and deterministic findings |
| **Campaigns** | Project-scoped campaign planning, checkpoints, reports and safe resume |
| **Governance** | Data classification, protection profiles, policies, recommendations and audit history |
| **Release** | CI validation, reproducible metadata, checksums, dependency review and release inspection |

### Current roadmap

**R1–R20** and **T7–T9** are implemented or actively developed on the feature branch, with later phases focused on deterministic evidence, assessment orchestration, reporting, regression, governance, and release integrity.

Wraith deliberately does **not** claim to be an exploitation framework, autonomous attack system, or definitive vulnerability oracle.

## Quick start

### Safe dashboard demo

No target or scan is required:

```bash
git clone https://github.com/Adam-Ghanem/Wraith.git
cd Wraith/web
pnpm install --frozen-lockfile
pnpm dev
```

Open the local Vite URL to inspect the bundled Phase 5 fixtures.

### Local-network discovery

```bash
./bin/wraith discover \
  --interface eth0 \
  --cidr 192.168.1.0/24 \
  --authorized \
  --format terminal
```

### Authorized web scan

```bash
./bin/wraith scan \
  -d example.com \
  --project project-a \
  --authorized \
  --db wraith.db
```

Use `--json` for machine-readable output and `history` for local scan diffs.

## Safety model

Every active web operation is constrained by project scope and bounded transport controls. Wraith favors:

- explicit authorization and target scope
- bounded rate, concurrency, timeout and response size
- read-only defaults where possible
- redacted secrets and secret-free persistence
- local evidence and provenance
- deterministic output and reproducible checks
- fail-closed behavior when scope or evidence is ambiguous

## Architecture

```text
                 ┌─────────────────────┐
                 │      Wraith CLI     │
                 └──────────┬──────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   Discovery             Web Recon           Campaigns
   R1 / local            R2–R5 / R3          R10.5 / R14+
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                     Evidence / SQLite
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
           Findings      Reports      Governance
           R11.5+        R16          R19–R20 / T7–T9
```

The web application provides the read-only evidence workspace and consumes sanitized local fixtures for its demo mode.

## Project layout

```text
Wraith/
├── cmd/              CLI entry points
├── internal/          discovery, transport, evidence and phase logic
├── web/               evidence dashboard
├── docs/              architecture, support, threat model and phase docs
├── docs/assets/       README and dashboard visuals
├── bin/               built CLI artifacts
└── tests/             integration and regression coverage
```

## Build & test

```bash
go test ./...
go build ./...
```

For the dashboard:

```bash
cd web
pnpm install --frozen-lockfile
pnpm build
```

CI is the source of truth for the complete validation matrix.

## Documentation

- [Support matrix](docs/support-matrix.md)
- [Architecture / phase documentation](docs/)
- [Threat model](docs/)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
