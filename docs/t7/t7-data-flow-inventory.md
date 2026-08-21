# T7 Data-Flow Inventory

## Production Flow Map

| Producer | Representation | Current downstream path | Data risk | T7 disposition |
|---|---|---|---|---|
| R3/R4 HTTP result | `HTTPObservationInput` | R2 constructor → `AppendObservation` | Response headers/title/server fields | Classify headers and metadata; redaction decision remains observable. |
| R7/R7.5/R8/R11.2 and R11.3 adapters | Typed observation inputs | R2 constructor → `AppendObservation` | Candidate/reproducibility/reference strings | Validate safe structured representation and preserve evidence status meaning. |
| R11.5 risk correlation | `SecurityFindingRecord` | `UpsertSecurityFinding` → reports | Descriptions, remediation, factors, reasons, refs | Reject or redact unsafe descriptive material before storage; never recompute risk score. |
| R14/R15 execution | Secret-minimized task context/result refs | Campaign and assessment storage/audit | Target query/userinfo and evidence references | Preserve T4/T5/T6 gates and validate representation in addition. |
| R16 report projection | `reportmodel.Snapshot` | `reporting.Render*` → stdout/file | All projected string fields | Use canonical T7 classification in snapshot/output gateway; preserve format-specific renderer behavior. |
| R17/R18/R19/R20/R21/R22 read models | Correlation, regression, control, governance, analytics, decision strings | Report snapshot/output | Reasons, limitations, lineage, source refs | Reject unsafe values before trust-sensitive snapshot/fingerprint use. |
| T3/T5 audit metadata | Typed authorization audit event | append-only audit table | Reason/scope/reference metadata | Retain current typed audit contract; T7 governance audit contains only safe subject references and classification metadata. |
| Legacy fixture export | Scan/history JSON | direct file output | Unclassified rendered JSON and direct scan invocation | Explicitly deny rather than silently export. |

## Sensitive Data Rules

Clearly secret material includes credential-bearing URLs, authorization/proxy-authorization values, cookie values, private-key material, bearer/basic credentials, JWT-like values, and values attached to canonical sensitive markers such as password, secret, token, API key, session, CSRF, or client secret. Names can be retained where useful and safe; values are redacted or blocked according to destination policy.

T7 does not infer secrets from entropy or length alone. Ordinary values are preserved within bounded representations. Classification uses semantic field context, canonical markers, source/destination purpose, and structured location.
