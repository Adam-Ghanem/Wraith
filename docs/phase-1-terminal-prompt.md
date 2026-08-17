# Wraith Phase 1 — Terminal Agent Prompt

You are working on **Wraith**, an open-source Go Web Attack Surface Management platform. Implement **Phase 1 only: Local Network Discovery**. Do not start Phase 2 or add unrelated features.

## Goal

Build a standalone Linux-first CLI command:

```text
wraith discover
```

It must discover devices on one explicitly selected local IPv4 interface/CIDR, scan a curated top-100 TCP port list, collect limited read-only service metadata, and output deterministic JSON plus a terminal table.

## Required features

- TCP connect scanning with `net.Dialer`.
- Curated, versioned top-100 TCP ports.
- Bounded goroutine worker pool.
- Per-connection timeout, total timeout, context cancellation, graceful shutdown, and clear errors.
- ARP discovery on the selected interface and directly connected IPv4 subnet using `github.com/mdlayher/arp`.
- IP, MAC, and offline OUI vendor lookup.
- Bounded read-only banners for common services such as SSH, FTP, SMTP, HTTP, and HTTPS.
- Best-effort OS/service heuristics only; every guess must include evidence, method, and confidence and be labeled `heuristic`.
- Versioned JSON output and deterministic terminal output.
- `--dry-run` that validates scope and sends no packets.
- `--no-banner` option.

## Strict exclusions

Do not add public or internet-wide scanning, arbitrary routed targets, UDP/SYN scans, packet spoofing, exploitation, credential testing, brute force, denial-of-service behavior, Nmap, Nuclei, masscan, ZAP, ffuf, web recon, subdomain enumeration, JavaScript analysis, SQLite, dashboard, API, authentication, scheduling, cloud enrichment, or external APIs.

## Safety rules

Before sending traffic, require and display exactly one interface and its directly connected IPv4 CIDR. Reject missing, ambiguous, non-local, routed, oversized, or invalid scope. Cap host count, worker count, request rate, banner bytes, and timeouts. Fail closed on invalid input.

ARP may require Linux `CAP_NET_RAW`; do not create a setuid/root binary. Provide an actionable privilege error and keep privileged tests opt-in on an owned isolated lab network. Never use public targets. Ordinary tests and CI must require neither root nor internet access.

## Recommended structure

```text
cmd/wraith/main.go
internal/cli/
internal/config/
internal/scope/
internal/model/
internal/discovery/ports/
internal/discovery/arp/
internal/discovery/fingerprint/
internal/discovery/vendor/
internal/output/
internal/testutil/
data/
testdata/
docs/
```

Keep CLI, validation, discovery adapters, fingerprinting, and output separate. Keep implementation under `internal/`.

## Build order

1. Inspect the repository and confirm the Go module/toolchain.
2. Define the Phase 1 scope and responsible-use documents.
3. Define configuration, scope validation, result models, and JSON/table output.
4. Implement `wraith discover --dry-run` and prove no network calls occur.
5. Implement one local TCP probe against a loopback listener.
6. Add the bounded worker pool and cancellation.
7. Add and validate the top-100 list.
8. Implement one-host ARP discovery, then bounded subnet ARP discovery.
9. Add offline OUI lookup.
10. Add bounded read-only banners and conservative service classification.
11. Add explicitly labeled low-confidence heuristics.
12. Integrate: scope → ARP → TCP → fingerprint → OUI → deterministic output.
13. Add documentation and acceptance tests.

## Required tests

Cover scope rejection, oversized CIDRs, invalid ports, TCP open/closed/timeout/error/cancel, worker cancellation, zero workers, duplicate ports, goroutine cleanup, race detection, ARP reply matching, ARP timeout/cancel/duplicates, privilege errors, OUI lookup, slow/truncated/oversized banners, `--no-banner`, JSON golden files, deterministic ordering, partial results, and dry-run no-network behavior.

Run:

```text
go test ./...
go test -race ./...
go vet ./...
```

Use loopback listeners, fake adapters, and fixtures in ordinary tests. Use an opt-in owned lab only for privileged ARP integration testing.

## Agent reporting rule

Before editing, inspect the repository and summarize relevant files. Work in small changes. For every change report files changed, tests run, network behavior, privilege impact, scope impact, known limitations, and deferred work. Do not claim completion because the code compiles.

## Definition of done

Phase 1 is complete only when the dry-run validates local scope without packets, TCP discovery works against a local listener, ARP works in an opt-in owned lab, JSON/table output is deterministic, banners and heuristics are bounded and uncertainty-labeled, privilege and partial failures are actionable, all tests/vet/race checks pass, and no Phase 2 or offensive functionality has been added.
