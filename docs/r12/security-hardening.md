# R12 Security Hardening

R12 preserves the existing security architecture and adds regression protection around it. It does not weaken R1 authorization, R3 transport, evidence redaction, project isolation, or resource limits.

| Boundary | R12 assurance |
| --- | --- |
| Authorization | Smoke coverage retains explicit `--authorized` gating on tested active/intelligence command paths. R1 remains authoritative for target policy. |
| HTTP and DNS | R12 creates no HTTP client, DNS resolver, socket, proxy, or direct transport. Existing approved R3 paths remain the only web transport boundary. |
| Secret handling | Temporary tests use no real credentials. R12 outputs and fixture records are limited to local synthetic project identities and redacted evidence. |
| Project isolation | Temporary SQLite smoke data proves one project’s assets do not appear in another project’s command output. |
| Resource controls | Existing request, response, duration, rate, concurrency, profile, and planner bounds are left in place. No configuration bypass is added. |
| Redirect and SSRF control | Existing R1/R3 policy, redirect reauthorization, and destination restrictions remain untouched; R12 has no alternate egress path. |
| Reporting and databases | R12 adds no report engine. SQLite remains local and must be backed up with restricted filesystem access. |
| CI supply chain | CI retains pinned actions, module verification, locked web installation, dependency review, production web audit, format/vet/test/race/build checks, and now runs R12 smoke/migration checks. |

The egress review records existing direct primitives only in their pre-existing subsystem owners: R3 HTTP engine/dial transport, R1-adjacent probe and enumeration functions, and explicitly bounded legacy external-tool wrappers. R12 introduces none. Any future direct egress or subprocess addition requires a separate architecture review and must not be hidden inside an integration test.
