# T4 Architecture — Derived Trust Context

T4 introduces `internal/trustcontext`, a pure deterministic authority that carries references to existing trust decisions rather than duplicating authorization or scope data. The carrier contains only project, authorization, scope, task, assessment, optional campaign, budget-reference, assurance, expiry, and canonical fingerprint fields. It deliberately excludes raw target URLs, headers, cookies, credentials, payloads, and evidence.

| Stage | Required proof | Enforcement result |
|---|---|---|
| T1 | Active, unrevoked record with valid canonical fingerprint | The derived context rejects expired, forged, mismatched, or cross-project records. |
| T2 | Canonical scope version and target membership | The derived context binds the exact scope version and scope fingerprint. |
| T3 | `execution_eligible` assurance | Lower assurance levels are rejected. |
| T4 | Task, assessment, optional campaign, budget reference, expiry, canonical fingerprint | The execution engine and adapter registry reject missing, expired, forged, or misbound carriers. |

The assessment CLI produces a fresh context immediately before each task by reloading T1/T2 authority, rerunning T3 classification, and deriving the T4 context. Before dispatch, the engine requires an append-only T3 authorization-audit assertion keyed by the non-secret task fingerprint; a failed audit write blocks the task. The engine independently validates the carrier and then passes it to the adapter registry. The registry independently validates it again before invoking any R15 owner.

```text
T1 record + T2 scope + task + budget
              │
              ▼
      T3 Classify (eligible)
              │
              ▼
   T4 derived, fingerprinted context
              │
              ▼
R13.2 engine revalidates ──► adapter registry revalidates ──► existing R3-backed owner
```

The context cannot outlive the active T1 authorization, cannot be replayed against another project, scope, task, assessment, or campaign, and cannot be repaired after fingerprint tampering. A missing context blocks non-dry execution before task dispatch.
