# T8 Security Review

T8 is a local, deterministic representation-protection authority. It adds no HTTP client, DNS resolver, socket, subprocess, scheduler, worker, remote store, telemetry, credential collection, credential store, target validation, or execution path. Its pure core imports only standard canonicalization utilities plus T7 classification/governance packages.

| Threat | Control |
|---|---|
| Caller downgrades a class or forges a descriptor | Closed T7 levels, canonical descriptor reconstruction, and SHA-256 fingerprint comparison fail closed. |
| Caller supplies a forged T7 decision | T8 revalidates policy and decision fingerprints and recomputes the deterministic decision for the requested subject/profile/time. |
| Cross-project snapshot retrieval | SQLite keys and queries include `project_id`; no fallback lookup is available. |
| Raw secret persistence or output | T7 owns bounded secret screening/redaction. T8 descriptors and snapshots accept only safe references and fingerprints, never values. |
| Unauthorized protected CLI operation | `data protect` requires `--authorized` plus an existing active T1 record bound to the supplied project and scope; acknowledgement alone is rejected. |
| Audit manipulation | Snapshot writes are insert-only and append a project-scoped secret-free T7 governance event in the same transaction. |

The implementation deliberately does not claim encrypted SQLite at rest, universal historical classification, a remote export channel, automatic retention deletion, or a multi-user authorization model. Existing report and analytics owners retain their immutable T7-safe projections; T8 adds explicit protected decision/snapshot operations without mutating their source state.
