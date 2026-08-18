# R5 Endpoint Discovery

R5 is a **passive, local endpoint inventory**. `wraith endpoints --project PROJECT --authorized` reads only project-scoped R2 endpoint, parameter, and asset records. It makes no network request, opens no socket, resolves no host, fetches no OpenAPI URL, executes no JavaScript, and changes no R2 record.

The output is deterministic: endpoints are ordered by canonical URL and method; parameters are ordered by stable R2 identity; assets are ordered by identity. It reports canonical endpoint identity, method, URL, parameter name, parameter location, and evidence classifications. Values, request bodies, response bodies, cookies, credentials, and authorization headers are not included.

| Classification | Passive evidence rule | Meaning |
| --- | --- | --- |
| `page` | Default canonical URL label | A known web route, not a security claim. |
| `form` | Non-GET/HEAD endpoint has an R2 `body` parameter | A form-shaped R4 discovery record; form values and enctype are not retained. |
| `api` | URL has an API/version, GraphQL, Swagger, or OpenAPI convention | An inventory hint, not proof of an API exposure. |
| `graphql` | Canonical URL contains a GraphQL convention | A candidate endpoint only; R5 never introspects or queries it. |
| `openapi` | Canonical URL has a Swagger/OpenAPI convention, or came from local parsing | A specification reference or local operation projection. |
| `javascript` | Canonical asset URL ends in `.js` | An existing R2 JavaScript asset; R6 performs any further static analysis. |

## Local OpenAPI and Swagger input

`--openapi FILE` accepts an explicit local **JSON** OpenAPI 3 or Swagger 2 document. The file is bounded to 1 MiB; parsing is limited to 2,000 paths and 5,000 operations. The parser reads declared server/base URL, paths, safe method declarations, and parameter names/locations, including JSON property names. It does not fetch a URL referenced in the document, execute an operation, use YAML, inspect GraphQL schemas, infer values, or persist new evidence.

## Project isolation and limits

R5 reads endpoints and parameters through project-filtered R2 repository methods. Cross-project input is rejected. Default inventory limits are 10,000 endpoints, 50,000 parameters, and 10,000 assets. A malformed or oversized local specification fails closed with generic parser or limit errors. The endpoint inventory is an evidence projection, not a finding, vulnerability, risk score, or report.

## Deferred to R6 and later

R5 deliberately defers JavaScript static intelligence, remote OpenAPI discovery/fetching, API execution, GraphQL operations or introspection, authentication contexts, fuzzing, security checks, findings, risk, reporting, queues, and distributed workers. Any future active request remains subject to R1 authorization and R3 transport controls.
