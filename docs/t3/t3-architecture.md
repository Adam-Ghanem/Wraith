# T3 Architecture — Security Trust and Operational Authority

## Assurance vocabulary

T3 makes four distinct facts visible rather than treating `--authorized` as a security proof.

| Assurance | Meaning | Source of truth |
|---|---|---|
| `acknowledged` | The operator supplied the required local acknowledgement flag. | CLI invocation only. |
| `recorded` | A canonical T1 record exists and passes integrity checks. | `internal/authorization`. |
| `validated` | The T1 record is active for the project, exact scope reference, and current time. | T1 validation. |
| `scope_bound` | A canonical T2 version accepts the canonical target under the validated T1 record. | T2 scope authority. |
| `execution_eligible` | The complete chain is valid for a task identity and the supplied R10.5 budget controls are present. | T3 execution gate. |

The levels are deterministic enums. An acknowledgement can never imply a recorded, validated, scope-bound, or execution-eligible state.

## Execution gate

`securitytrust.ExecutionGate` is a pure, no-I/O decision layer. The integration owner supplies already-loaded T1/T2 records and an explicit task identity. The gate delegates T1/T2 validation to existing pure owners; it does not read SQLite, make HTTP/DNS requests, consume a budget, dispatch an adapter, or create a transport.

The assessment CLI and R13.2 engine use its result at their existing authorization seam. R10.5 continues to own budget consumption, rate waiting, and concurrency acquisition; R3 continues to own HTTP/DNS/destination/redirect enforcement.

## Audit event model

T3 audit events are append-only project-scoped records. Each includes project, authorization ID, scope reference, event type, UTC timestamp, bounded reason code, immutable sequence key, and canonical fingerprint. Values with secret-like markers or credential-bearing URLs are rejected before persistence.

Audit events describe local lifecycle and policy decisions only. They do not assert real-world ownership proof, remediation, or security of a target.

## Data classification

T3 applies a lightweight local classification at trust/audit boundaries:

| Class | Use |
|---|---|
| `public` | Non-sensitive command labels and static release metadata. |
| `internal` | Project-scoped operational identifiers and bounded local diagnostics. |
| `security_sensitive` | Evidence/finding/audit metadata that must retain project isolation and restrictive output handling. |
| `secret_forbidden` | Credentials and credential-bearing material; it must be rejected rather than persisted or rendered. |

The model does not add encryption-at-rest. SQLite encryption and filesystem-at-rest controls remain deployment responsibilities documented in the T3 data-classification contract.
