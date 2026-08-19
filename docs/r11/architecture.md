# R11.1 Architecture

> **R11.1 is a planning-only boundary. It does not perform network I/O.**

```text
R2 Endpoint + Parameter identities
        │
        ▼
R11.1 PlanInput ── validation, project match, limits, secret-header rejection
        │
        ▼
immutable RequestVariant values ── non-reversible request fingerprints
        │
        ▼
future approved executor only: R1 policy → R3 HTTP engine → network
```

The package imports `evidence` for canonical endpoint and parameter identities. It has no dependency on an HTTP client, resolver, socket, subprocess, or storage writer. The templates are copied before a mutation is applied; their request bodies and headers remain memory-only. Serializable plan fields contain structural identities, strategy names, counts, and SHA-256 fingerprints only.

The R11.1 input requires a current operator authorization assertion and uses the caller’s project ID to reject mismatched R2 records. It rejects sensitive headers—including `Authorization`, `Cookie`, API-key, and access-token names—rather than attempting to copy or transform them. A later executor must independently use R1 and R3; candidate creation is not evidence of authorization to send a request.
