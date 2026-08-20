# T1 Security Review — Authorization Lifecycle

## Security objective

T1 replaces an otherwise ephemeral operator assertion with a durable local authorization record. It deliberately does **not** assert that Wraith can prove ownership of arbitrary targets from CLI input. A record is an auditable, time-bounded authorization assertion that must later be combined with R1 scope evaluation and the T2/T3 centralized authority path.

## Threats and controls

| Threat | Control | Fail-closed outcome |
|---|---|---|
| Forged or modified record | Canonical SHA-256 fingerprint validated before use. | Validation returns `authorization fingerprint mismatch`. |
| Cross-project use | Storage lookup and validation both require the exact project ID. | No record is returned or accepted. |
| Wrong scope reference | Validation requires exact opaque scope-reference equality. | Validation returns `authorization scope mismatch`. |
| Expiry/revocation bypass | UTC-bound expiry and explicit revocation state are checked at validation. | Record is rejected. |
| Secret persistence | References reject credential-bearing URLs, headers, cookies, bearer values, passwords, API-key markers, and private-key markers. | Record creation rejects unsafe input. |
| Unapproved lifecycle mutation | Creation is insert-only; revocation updates only the matching active fingerprint and records a new lifecycle fingerprint. | Update fails if prior state is missing or changed. |
| Recommendation/operation confusion | T1 does not execute network requests or security operations. | No HTTP, DNS, socket, subprocess, scheduler, worker, or scanner is introduced. |

## Residual limitation and migration

Existing commands retain `--authorized` during T1. The new `wraith authorization` commands require it for an explicit audit trail, but T1 does not claim all existing active operations are already bound to a lifecycle record. T2 will centralize scope semantics and T3 will centralize egress enforcement; until then, a record is available for validated adoption and fails closed whenever it is used.
