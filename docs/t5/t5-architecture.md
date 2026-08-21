# T5 Architecture: Policy Gateway and R3 Delegation

## Gateway Model

`internal/outbound` is a pure policy package. `Gateway.Authorize` validates a prospective operation and returns an in-memory decision. It does not dispatch a request. `Client.Do` validates the constrained R3 request, calls the gateway, and only then delegates to the injected R3 interface.

> **The gateway is fail-closed.** A missing or invalid authority, expired operation, project mismatch, scope denial, budget mismatch, or audit failure prevents dispatch.

| Stage | Authority or control | Denial behavior |
|---|---|---|
| 1 | Credential-material detector | Rejects before target parsing. |
| 2 | Operation identity and expiry validation | Rejects malformed or expired operations. |
| 3 | T4 `trustcontext.Validate` | Rejects absent, forged, stale, or cross-project derived trust. |
| 4 | Explicit capability registry | Rejects unknown capabilities, duplicate ownership, or insufficient assurance. |
| 5 | T2 outbound target gateway | Rejects targets outside the project scope. |
| 6 | Budget-reference binding | Rejects missing or trust-mismatched budget references. |
| 7 | T3 append-only audit store | Rejects when the allow decision cannot be written. |
| 8 | R3 delegation | Invoked only for a successful, audited decision. |

The registry is intentionally small. `DefaultRegistry()` names only two capability IDs and owners. Capability strings are not user-controlled permits: each entry is hard-coded code review surface with an assurance requirement and scope and budget flags.

## Request Contract

`outbound.Client` takes an injected `httpengine.Client`. It never calls an HTTP constructor and never imports `net/http`, `net`, `net/url`, or `os/exec`. The client requires the operation project and destination to equal the R3 request fields. Only `GET` and `HEAD` are accepted; bodies, `Authorization`, and `Cookie` headers are rejected. These checks reduce the delegated operation to a bounded read seam while retaining R3 as the sole transport implementation.

The crawl adapter sets `manageControls` because its established R10.5 lifecycle remains its responsibility. Smart discovery leaves this false because its verifier already owns that control lifecycle. T5 neither duplicates nor bypasses those controls.

## Offline Operator Diagnostics

`wraith outbound status [--json]` lists only the compiled capability registry and reports `dispatch=false`. `wraith outbound explain --capability ID [--json]` describes one capability. Neither command opens a database, constructs a transport, parses a target, or sends a request.
