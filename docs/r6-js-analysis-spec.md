# R6 — JavaScript and Client-Side Intelligence Specification

## Status and objective

R6 adds a **local, deterministic static-analysis layer** for JavaScript assets that are already represented in R2 evidence and for explicitly supplied local files. It enriches the existing R2/R5 attack surface with statically provable client-side references. It does not browse, fetch, resolve, submit, execute, fuzz targets, scan for vulnerabilities, or create findings.

## Non-negotiable boundaries

The R6 package must not import `net`, `net/http`, `os/exec`, a JavaScript runtime, browser automation, or R3 transport code. It accepts bytes already supplied by an R2-backed source or an operator-specified local path. No discovered URL, source-map reference, endpoint, WebSocket, or GraphQL operation is followed or invoked.

Existing Phase 3 active JavaScript collection remains untouched in its existing functions and continues to use R3. R6 is a separate passive path in the same package namespace and may not call `AnalyzeHTML`, `AnalyzePage`, or `fetchJS`.

## Parser and syntax contract

R6 uses `github.com/tdewolff/parse/v2/js` as a maintained MIT-licensed Go parser. It supports module parsing and the modern syntax accepted by that parser, including common ES module, async/await, arrow-function, class, destructuring, optional-chain, nullish-coalescing, and bundled/minified forms. Parsing errors are converted into bounded generic diagnostics; unsupported syntax yields no inferred references from an AST traversal.

The parser is used only to validate and traverse static syntax. Literal-oriented extractors may retain useful, bounded lexical signals when an input fails to parse, but must label the syntax state and must not evaluate expressions or guess values.

## Inputs, scope, and limits

| Input | Rule |
| --- | --- |
| R2 JavaScript assets | Only assets returned by a project-filtered repository read are eligible. Asset URLs identify provenance; R6 does not download their bodies. |
| Local JavaScript files | An explicit `--file` path is read locally under the same byte and file-count limits. It is associated with a deterministic local provenance identifier, but never causes a URL fetch. |
| Local source maps | A source map is read only when explicitly supplied. `sourceMappingURL` comments are recorded as references and are never dereferenced. |
| Project isolation | Every repository read/write accepts the command project ID. Cross-project source data is rejected. |
| Per-file JS size | 2 MiB by default; configuration can only lower this ceiling or raise it to the documented hard ceiling. |
| Files per run | 100 by default; hard ceiling 1,000. |
| AST nodes | 100,000 by default; traversal stops deterministically at the limit. |
| Extracted records | Per-kind caps prevent URL, route, parameter, source-map, technology, and source/sink output growth. |
| Source maps | 2 MiB, 1,000 sources, and 256 KiB mappings by default. |

All output is canonicalized, deduplicated, and sorted. Limit breaches and malformed input fail closed for that input without panicking or widening scope.

## Static extraction contract

R6 reports source location, source asset/local-file provenance, deterministic confidence (`high`, `medium`, or `low`), and a short structural evidence label. It never stores JavaScript source bodies, raw request-body values, headers, cookie values, tokens, or alleged secrets.

| Signal | Required evidence | Confidence |
| --- | --- | --- |
| URL/API route | A static string/template with no unresolved expression, or a recognized call argument | `medium`; `high` for a recognized HTTP-client call with a static URL |
| HTTP method | An explicit recognized `fetch` method option, `XMLHttpRequest.open` method, or Axios shorthand/configuration | `high` |
| Dynamic template | A literal template with unresolved interpolations normalized to `{parameter}` | `medium` when a request-client context is recognized; otherwise `low` |
| Parameter | A static query key, object key, `URLSearchParams`, `FormData`, or JSON-body key | `high` in a recognized request; otherwise `medium` |
| WebSocket | A static `new WebSocket` URL or `ws://`/`wss://` literal | `high` for constructor; otherwise `medium` |
| GraphQL | Static `/graphql` reference, known client identifier, or literal query/mutation operation name | `high` for operation syntax; otherwise `medium` |
| Client route | Static path in recognized React/Vue/Angular route configuration | `high`; standalone route-like literal is not a route claim |
| Technology | Multiple structural signals for one technology | `medium` or `high`; a bare string alone is ignored |
| Client source/sink | Recognized structural API or member access such as `location`, `document.cookie`, `innerHTML`, or `eval` | `high` |

Recognized request clients are `fetch`, `XMLHttpRequest`, Axios shorthand/configuration, and narrowly identified common wrappers. A generic function named `request` is not reported as HTTP activity without supporting evidence.

## Evidence and R5 correlation

R6 reuses `evidence.WebAsset`, `evidence.Endpoint`, `evidence.Parameter`, and append-only `evidence.Observation` identities. Static HTTP references produce canonical R2 endpoints and parameters through the existing constructors, so an R5 endpoint is upserted rather than duplicated. Existing endpoint identity is `METHOD URL`; unknown method references use `GET` only when the source is an explicit URL asset or URL literal without a method claim, and output must distinguish that default from an extracted method.

Client-side metadata is appended to the originating JavaScript asset as bounded typed payloads with source names such as `jsanalysis.url`, `jsanalysis.api`, `jsanalysis.websocket`, `jsanalysis.route`, `jsanalysis.sourcemap`, `jsanalysis.technology`, `jsanalysis.client_source`, and `jsanalysis.client_sink`. A migration extends the allowed observation-kind set to include `client_side`; observations remain append-only.

Sensitive-looking parameter names may be marked only as `sensitive_parameter_reference`. Their values are neither extracted nor persisted. This is descriptive client-side evidence, not a vulnerability, credential leak, risk score, or finding.

## CLI contract

`wraith js --project PROJECT --authorized [--db PATH] [--asset ID] [--file FILE] [--sourcemap FILE] [--max-files N] [--max-size BYTES] [--json]` performs a local bounded analysis. At least one input selector is required. `--asset` must resolve only within the named project. The terminal and JSON representations expose deterministic assets, URLs/templates, API methods, parameters, WebSockets, GraphQL references, source maps, routes, technologies, and client-side source/sink metadata.

## Explicit R6 exclusions

R6 excludes JavaScript/WebAssembly execution, browser automation, source-map or JavaScript downloading, any outbound request, GraphQL execution or introspection, form submission, fuzzing, credential testing, vulnerability checks, findings/risk/reporting, worker systems, PostgreSQL/Redis, and architecture redesign. R7 is separately scoped after R6 completion.
