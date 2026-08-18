# Wraith Threat Model

## Purpose and security posture

This document identifies security-relevant assets, trust boundaries, and residual risks for the implemented Phase 1–6 feature set plus the R3 target-web transport branch. It is a design review, not a claim that Wraith is secure, a penetration-test report, or a guarantee that every threat has been eliminated.

Wraith intentionally performs network-adjacent activity only after an operator supplies the required command flags and authorization confirmation. The tool cannot independently verify legal ownership, contractual authorization, target safety, or the correctness of fixture data. Those are operator and organizational controls defined by [`responsible-use.md`](responsible-use.md).

## Assets and trust boundaries

| Asset | Why it matters | Primary boundary |
| --- | --- | --- |
| Authorization record and selected scope | Prevents unauthorized network activity and scope drift. | `--authorized`, project-scoped R1 policy records, and `scan --project` for migrated target-web activity. |
| R3 request, resolution, proxy path, and connection pool | Can induce egress, carry sensitive headers, or exhaust local resources. | R1 before I/O, controlled resolver/pinned dial, reserved-address filtering, explicit proxy configuration, redaction, bounded body/rate/concurrency/retry controls, and TLS verification. |
| Local host and network availability | Aggressive or misdirected traffic can disrupt the operator's environment or approved target. | Bounded discovery/probing design, timeouts, rate/parallelism settings, and explicit optional-tool flags. |
| Scan results, SQLite data, JSON, and fixtures | May expose asset names, headers, content paths, JavaScript-derived strings, service metadata, and timestamps. | Local filesystem access, output handling, and operator-controlled distribution. |
| Optional API credentials | `VT_API_KEY`, when configured for the existing Phase 2 optional VirusTotal source, is sensitive. | Process environment, shell history, CI/secrets handling, and user-controlled source enablement. |
| Release artifacts and dependencies | A modified binary, CI action, or dependency can compromise the operator environment or falsify results. | SHA-pinned Actions, locked dependencies, module checksums, package review, and checksum publication. |
| Static dashboard rendering | Fixture-controlled values can be hostile or misleading if rendered unsafely. | React rendering, UI test coverage for text rendering, local/offline architecture, and no dashboard backend. |

## Trust-boundary map

```text
Operator authorization and CLI options
        |
        v
Wraith CLI ---- policy-aware R3 target-web activity ----> authorized domains / web origins
        |                                               \
        |                                                -> documented optional public enumeration sources
        v
Local SQLite, JSON, and exported fixtures ----> static local Phase 5 dashboard
        |
        v
Operator-controlled retention and sharing

Optional executables: nmap and nuclei are separate subprocess trust boundaries.
```

## Threats, controls, and residual risk

| Threat | Potential impact | Current controls | Residual risk / operator action |
| --- | --- | --- | --- |
| Incorrect or expired authorization | Unauthorized discovery or web requests. | Explicit authorization requirement plus R1 project-scoped scope/approval evaluation for every migrated HTTP target and resolved address. | Wraith cannot prove ownership or permission. The operator must validate authorization before every run and maintain an active scope. |
| Scope expansion through DNS, redirects, JavaScript, or discovered hosts | Requests to out-of-scope infrastructure. | R3 manually reauthorizes redirects, pins controlled DNS results, filters unsafe addresses, and preserves same-host collector rules. | Provider APIs and optional binaries are documented exceptions, not inherited R3 coverage. |
| SSRF-like pivoting or unexpected outbound requests | Access to internal/private services or unapproved origins. | R3 rejects loopback, private, link-local, multicast, CGNAT, documentation, benchmark, and reserved ranges by default; proxy configuration is explicit and target authorization happens before proxy connection. | A selected proxy is still a trusted transport path; Wraith does not provide proxy attestation or a distributed egress firewall. |
| Retry, rate, or connection exhaustion | Duplicate state changes, request bursts, or too many sockets. | One-attempt retry default; unsafe methods are not replayed by default; cancellation-aware local rate/concurrency limits and reusable bounded idle pool. | Limits are local to the process and are not a cross-process quota service. |
| Sensitive values in content/JavaScript findings | Disclosure of credentials, internal endpoints, or operational details. | Phase 3 policy requires minimization, redaction, secure storage, and prohibits credential validation. | A finding is not proof of a real secret. Operators must apply their organization's incident/secret-handling process. |
| Optional Nmap/Nuclei subprocess behavior | Broader network effects, privilege needs, template behavior, or tool compromise. | Both are explicitly opt-in; absence is non-fatal; policy requires separate approval. | Review the installed binary, version, flags/templates, and its own licensing/security guidance before use. |
| Unsafe rendering of fixture-controlled strings | Dashboard script execution, spoofed UI, or misleading analysts. | Static dashboard has no backend/network API; tests confirm scan-derived strings render as text. | Keep dependencies current and treat fixture data as untrusted. The dashboard does not authenticate or validate data provenance. |
| Local data disclosure | Unauthorized access to databases, JSON, dashboards, or exported fixtures. | Local-first design and policy requiring restricted access and retention controls. | Wraith does not encrypt data at rest or operate an access-control service; secure the host and filesystem. |
| Dependency or CI supply-chain compromise | Compromised build, developer environment, or release artifact. | SHA-pinned GitHub Actions, Go module verification, frozen pnpm lockfile, exact frontend dependency declarations, documented review, and CI coverage check. | Pinning reduces tag-drift risk but does not eliminate upstream compromise. Review updates and verify checksums through a trusted channel. |
| Tampered binary distribution | Users run a modified artifact. | `make sha256sums` emits SHA-256 checksums; release metadata is shown by `wraith version`. | Artifacts are not signed and no provenance attestation exists. Do not treat checksums as publisher authentication. |
| Misleading absence or success results | False assurance, missed assets, or incorrect risk conclusions. | Output-limitations policy and explicit per-phase non-proof statements. | Operators must communicate omissions, errors, and uncertainty; use separately authorized assessment methods for security conclusions. |

## Out of scope and explicit non-goals

The current project does not claim to provide authentication, multi-user authorization, encrypted result storage, remote API access, scan scheduling, proxy credential storage, provider-policy enforcement, signed releases, vulnerability remediation, automated exploitation, credential validation, or a comprehensive vulnerability-management program. The Phase 5 dashboard is deliberately static and local rather than a hosted multi-user service.

External public enumeration is limited to the sources already implemented by the current Phase 2 workflow, including the optional VirusTotal source when `VT_API_KEY` is configured. This is a data-source boundary, not authorization to query arbitrary third-party services, upload scan output, or use Wraith as an external integration platform.

## Security review triggers

A new threat-model review is required before adding a new network protocol, target class, credential flow, external data sink/source, persistent process, scheduler, dashboard backend, authentication system, optional binary, file-upload path, dependency family with materially different licensing, or release-signing/provenance process.

Security defects in the current implementation should follow the process in [`../SECURITY.md`](../SECURITY.md). Unauthorized use must instead be stopped and handled under [`responsible-use.md`](responsible-use.md).

## References

This is repository-specific technical documentation. Its implementation references are the Phase 1–5 CLI and dashboard source, [`dependency-review.md`](dependency-review.md), [`release-process.md`](release-process.md), [`support-matrix.md`](support-matrix.md), [`responsible-use.md`](responsible-use.md), and [`../SECURITY.md`](../SECURITY.md).
