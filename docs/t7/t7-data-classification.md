# T7 data classification and consumer policy

T7 has two linked but separate responsibilities. `internal/dataclassification` identifies and minimizes unsafe raw representations before any fingerprint, storage, report, audit, CLI, JSON, Markdown, or HTML path can receive them. `internal/datagovernance` makes a deterministic policy decision for an already-governed subject and consumer. Neither package performs I/O, network dispatch, secret storage, or authorization creation.

| Ordered classification | Default treatment |
|---|---|
| `public` | Allow only when the named consumer policy permits it. |
| `internal` | Allow within a project-scoped policy boundary. |
| `sensitive` | Preserve only a redacted projection. |
| `restricted` | Preserve only metadata when explicitly permitted; otherwise deny. |
| `secret` | Never retain raw; the raw classifier redacts or rejects it before T7 policy evaluation. |

The supported consumers are local storage, technical and executive reporting, CLI output, JSON/Markdown/HTML export, audit logs, analytics, and egress. Egress is a representation decision only. T5/T6/R3 retain authority to allow and dispatch any outbound operation, and T7 cannot add a direct client, provider path, resolver, socket, subprocess, or automatic export.

Policy fingerprints, decision fingerprints, and retention fingerprints use canonical SHA-256 inputs. A stored fingerprint is recomputed before it is trusted. Unknown consumers, cross-project policy use, malformed identifiers, duplicate consumer rules, unsafe references, invalid classifications, and forged records fail closed.
