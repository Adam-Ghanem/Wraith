# T7 governance audit model

T7 keeps append-only, project-scoped, secret-free governance audit events. The existing migration-025 event stream records classification/redaction/persistence/export outcomes. The migration-026 policy, decision, retention, and event tables add the central governance authority without altering legacy evidence or T1 authorization audit ownership.

Audit references must be safe identifiers rather than raw targets, headers, cookies, tokens, credentials, private keys, or credential-bearing URLs. Stored rows are revalidated after hydration and reject forged fingerprints. Policy creation records a safe event only after the policy has passed T1 lifecycle validation and has been persisted successfully. Read-only inspection does not mutate audit state.
