# Security Policy

**Status:** A private security-reporting channel has **not yet been published** by the project owner.

## Scope

This policy concerns security defects in the Wraith source code, build process, release artifacts, CI configuration, and documentation that could cause a user or an authorized target to be harmed. Examples include command injection, unintended network activity beyond an explicitly authorized target, exposure of secrets through output or fixtures, insecure dependency handling, and vulnerabilities in the static dashboard.

> **Misuse of Wraith against targets without explicit authorization is a policy violation by the operator. It is not, by itself, a Wraith security vulnerability or a CVE.**

Reports about a suspected defect should state the affected revision, component, reproducible steps, observed impact, and any relevant non-sensitive logs. Do not include credentials, private target data, scan output containing sensitive information, or exploit code in a public issue.

## Reporting channel

The project owner must publish a private reporting channel before claiming a private disclosure process. Until then, a reporter may use the project owner's public GitHub profile at <https://github.com/Adam-Ghanem> to request a safe private contact method. The reporter should disclose only the minimum information necessary to arrange that channel; public GitHub issues are **not** a suitable place for sensitive technical details.

This is deliberately a placeholder rather than a fabricated email address or a promise that a GitHub communication feature is enabled. The owner should replace this section with a monitored, private reporting address or platform before distributing releases broadly.

## Handling expectations

Wraith makes no guaranteed response-time, remediation-time, bounty, or disclosure promise at this stage. After a private channel is available, the project owner should acknowledge a report, determine whether it is in scope, reproduce it where possible, coordinate a remediation plan, and agree on disclosure timing with the reporter. A public advisory should avoid exposing affected users or targets before a practical mitigation is available.

| Report category | Handling path |
| --- | --- |
| Security defect in Wraith code, release workflow, dependencies, or dashboard | Request a private channel through the owner profile and provide minimum non-sensitive context. |
| Unauthorized use of Wraith against a third-party target | Stop the activity, notify the affected owner as appropriate, and follow the responsible-use policy. |
| Product feature request, support question, or general bug with no security impact | Use the normal public repository issue process once the project owner enables it. |
| Sensitive credentials, private scan results, or target data | Do not submit them publicly; first arrange a private channel with the project owner. |

## Supported security baseline

The current baseline is defined by the active `main` branch and any checked release artifacts accompanied by a `SHA256SUMS` file. Releases are **checksummed, not signed**. A checksum helps detect accidental or malicious alteration after a trusted checksum has been obtained separately; it does not establish publisher identity.

T9 release trust is under feature-branch development. Its intended boundary is offline, explicit-local-trust-root verification of canonical manifests, provenance, artifact digests, and Ed25519 signatures. It does not publish releases, retrieve remote keys, accept production private signing keys, automate key rotation, or change the active `main` release baseline until separately reviewed and merged.

## References

This policy defines current project process and intentionally cites no external authority. The behavior and authorization constraints referenced here are documented in [`docs/responsible-use.md`](docs/responsible-use.md).
