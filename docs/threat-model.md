# Wraith Threat Model

## Purpose and security posture

This document identifies security-relevant assets, trust boundaries, and residual risks for the implemented Phase 1–5 Wraith feature set. It is a design review, not a claim that Wraith is secure, a penetration-test report, or a guarantee that every threat has been eliminated.

Wraith intentionally performs network-adjacent activity only after an operator supplies the required command flags and authorization confirmation. The tool cannot independently verify legal ownership, contractual authorization, target safety, or the correctness of fixture data. Those are operator and organizational controls defined by [`responsible-use.md`](responsible-use.md).

## Assets and trust boundaries

| Asset | Why it matters | Primary boundary |
| --- | --- | --- |
| Authorization record and selected scope | Prevents unauthorized network activity and scope drift. | Operator input, local interface/CIDR/domain options, and `--authorized` semantics. |
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
Wraith CLI ---- outbound, approved protocol activity ----> authorized local network / domains / web origins
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
| Incorrect or expired authorization | Unauthorized discovery or web requests. | Explicit authorization requirement, Phase-specific responsible-use rules, and fail-closed guidance. | Wraith cannot prove ownership or permission. The operator must validate authorization before every run. |
| Scope expansion through DNS, redirects, JavaScript, or discovered hosts | Requests to out-of-scope infrastructure. | Policy forbids output-derived scope expansion; Phase 1 local CIDR is explicit. | Phases 2–4 depend on the operator's domain/origin policy. Stop if a target is not clearly authorized. |
| SSRF-like pivoting or unexpected outbound requests | Access to internal/private services or unapproved origins. | Bounded command implementation and policy requiring approved domains/origins. | Treat URL, redirect, DNS, and JavaScript values as untrusted; approve scope before use and do not infer permission from reachability. |
| Sensitive values in content/JavaScript findings | Disclosure of credentials, internal endpoints, or operational details. | Phase 3 policy requires minimization, redaction, secure storage, and prohibits credential validation. | A finding is not proof of a real secret. Operators must apply their organization's incident/secret-handling process. |
| Optional Nmap/Nuclei subprocess behavior | Broader network effects, privilege needs, template behavior, or tool compromise. | Both are explicitly opt-in; absence is non-fatal; policy requires separate approval. | Review the installed binary, version, flags/templates, and its own licensing/security guidance before use. |
| Unsafe rendering of fixture-controlled strings | Dashboard script execution, spoofed UI, or misleading analysts. | Static dashboard has no backend/network API; tests confirm scan-derived strings render as text. | Keep dependencies current and treat fixture data as untrusted. The dashboard does not authenticate or validate data provenance. |
| Local data disclosure | Unauthorized access to databases, JSON, dashboards, or exported fixtures. | Local-first design and policy requiring restricted access and retention controls. | Wraith does not encrypt data at rest or operate an access-control service; secure the host and filesystem. |
| Dependency or CI supply-chain compromise | Compromised build, developer environment, or release artifact. | SHA-pinned GitHub Actions, Go module verification, frozen pnpm lockfile, exact frontend dependency declarations, documented review, and CI coverage check. | Pinning reduces tag-drift risk but does not eliminate upstream compromise. Review updates and verify checksums through a trusted channel. |
| Tampered binary distribution | Users run a modified artifact. | `make sha256sums` emits SHA-256 checksums; release metadata is shown by `wraith version`. | Artifacts are not signed and no provenance attestation exists. Do not treat checksums as publisher authentication. |
| Misleading absence or success results | False assurance, missed assets, or incorrect risk conclusions. | Output-limitations policy and explicit per-phase non-proof statements. | Operators must communicate omissions, errors, and uncertainty; use separately authorized assessment methods for security conclusions. |

## Out of scope and explicit non-goals

The current project does not claim to provide authentication, multi-user authorization, encrypted result storage, remote API access, scan scheduling, public-target safety validation, signed releases, vulnerability remediation, automated exploitation, credential validation, or a comprehensive vulnerability-management program. The Phase 5 dashboard is deliberately static and local rather than a hosted multi-user service.

External public enumeration is limited to the sources already implemented by the current Phase 2 workflow, including the optional VirusTotal source when `VT_API_KEY` is configured. This is a data-source boundary, not authorization to query arbitrary third-party services, upload scan output, or use Wraith as an external integration platform.

## Security review triggers

A new threat-model review is required before adding a new network protocol, target class, credential flow, external data sink/source, persistent process, scheduler, dashboard backend, authentication system, optional binary, file-upload path, dependency family with materially different licensing, or release-signing/provenance process.

Security defects in the current implementation should follow the process in [`../SECURITY.md`](../SECURITY.md). Unauthorized use must instead be stopped and handled under [`responsible-use.md`](responsible-use.md).

## References

This is repository-specific technical documentation. Its implementation references are the Phase 1–5 CLI and dashboard source, [`dependency-review.md`](dependency-review.md), [`release-process.md`](release-process.md), [`support-matrix.md`](support-matrix.md), [`responsible-use.md`](responsible-use.md), and [`../SECURITY.md`](../SECURITY.md).
