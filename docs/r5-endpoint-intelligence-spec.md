# R5 Endpoint and Attack-Surface Intelligence Specification

## Scope and boundary

R5 is a **passive, project-scoped inventory** over R2 records produced by R3/R4. It answers: *which endpoints, HTTP methods, parameter names and locations, form-shaped endpoints, API references, OpenAPI/Swagger references, and GraphQL references are already known for one project?* It performs **zero network I/O**. It creates no HTTP client, resolver, socket, crawler, fuzzer, JavaScript runtime, finding, risk score, or report.

| Input | R5 treatment | Safety boundary |
| --- | --- | --- |
| R2 endpoints and parameters | Deterministic sorted inventory, grouping, classification, and counts. | Reuse `Endpoint.Identity` and `Parameter.Identity`; never create a parallel identity. |
| R2 URL and JavaScript assets | Deterministic API/OpenAPI/GraphQL reference classification from canonical URLs. | Existing project-filtered repository reads only. |
| R4 form persistence | A form-shaped endpoint is an existing non-GET endpoint with one or more `body` parameters. | Only method, action URL, and parameter names are represented; values and bodies remain absent. |
| Optional local OpenAPI document | Explicit caller-provided bytes are parsed under size, depth, and operation limits. | Local input only; R5 never fetches a specification URL. |

## Data model and limits

R5 adds a narrow passive `endpointintelligence.Inventory` projection rather than a new database entity. The projection exposes canonical R2 endpoint URL/method identity, parameter names and locations, classifications, and source references. Default limits are 10,000 endpoints, 50,000 parameters, 1 MiB local OpenAPI input, 2,000 OpenAPI paths, and 5,000 operations. Inputs exceeding a limit fail closed with a generic limit error; malformed documents are rejected without leaking their content.

Endpoint classes are deterministic and non-security claims: `page`, `form`, `api`, `openapi`, `graphql`, and `javascript`. A classification is an evidence label only, not proof of an exposed service or a vulnerability. API-like names are recognized from path segments and common OpenAPI/GraphQL filename/route conventions. GraphQL detection never runs introspection or a query.

## CLI contract

`wraith endpoints --project PROJECT --authorized [--db PATH] [--json] [--openapi FILE]` is a local read and parse command. The authorization flag retains CLI consistency and explicit operator attestation; it does not cause network activity. The optional `--openapi` file is bounded before parsing and must be valid JSON or YAML-free JSON OpenAPI/Swagger content. Its operations are converted through `evidence.NewEndpoint` and `evidence.NewParameter`, then included in output only; R5 does not infer or persist request values.

## Threat model

Untrusted inputs include persisted URLs, parameter names, observation metadata, and local OpenAPI bytes. R5 mitigates resource exhaustion through page/parameter/spec/path/operation limits; protects project isolation through required project-filtered repository reads; protects sensitive information by reporting names and canonical identities only; and avoids SSRF/redirect/DNS risk through its zero-network design. Any future active OpenAPI retrieval, JavaScript static analysis, API testing, GraphQL querying, fuzzing, authentication use, findings, or reporting belongs to R6 or later and must use R1/R3 where active network activity is introduced.

## Acceptance criteria

R5 is complete only when project-isolated R2 endpoint/parameter/asset reads exist; inventory and classifications are deterministic; malformed/oversized inputs fail closed; optional local OpenAPI parsing is bounded; CLI terminal/JSON output works; no R5 package uses direct network APIs; unit, SQLite integration, isolation, malformed-input, resource-limit, fuzz, and benchmark coverage pass; documentation reflects reality; and R6 remains unstarted.
