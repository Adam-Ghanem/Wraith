# R6 JavaScript and Client-Side Intelligence

R6 adds a **bounded static-analysis workflow** for an explicitly supplied local JavaScript file. `wraith js --project PROJECT --authorized --file FILE` never downloads the file, opens a browser, evaluates JavaScript, resolves a hostname, creates a socket, or sends an HTTP request. A local source map can be inspected only when supplied with `--sourcemap FILE`; a `sourceMappingURL` comment is evidence, not an instruction to fetch content.

When `--asset ID` identifies a JavaScript asset belonging to the specified project, R6 correlates recognized static HTTP references with the existing R2 endpoint and parameter identities and appends client-side observations to that asset. `--asset` never selects an asset from another project. Without `--asset`, the command remains local-output-only because no canonical R2 JavaScript asset provenance is available for persistence.

## Parser, supported syntax, and limits

R6 validates JavaScript with the MIT-licensed `github.com/tdewolff/parse/v2/js` parser and performs a bounded AST traversal. It supports the module and modern JavaScript syntax accepted by that parser, including common async/await, arrows, classes, destructuring, optional chaining, nullish coalescing, and bundle/minified forms. Parse errors return an unparsed, empty static report without execution or a crash.

| Limit | Default | Hard ceiling | Behavior |
| --- | ---: | ---: | --- |
| JavaScript file | 2 MiB | 8 MiB | Oversized input is rejected. |
| Parse and traversal budget | 2 seconds | 10 seconds | A completed parser/traversal exceeding the budget is rejected. |
| AST nodes | 100,000 | 500,000 | Traversal stops and rejects the input. |
| Extracted records | 10,000 | 50,000 | Output-volume exhaustion fails closed. |
| Source-map file | 2 MiB | 2 MiB | Oversized or malformed local JSON is rejected. |
| Source-map sources | 1,000 | 1,000 | The local map is rejected beyond the limit. |
| Source-map mappings | 256 KiB | 256 KiB | The local map is rejected beyond the limit. |

## Extraction and confidence rules

The following signals are static evidence, not vulnerability claims. All output is deduplicated and deterministically sorted.

| Output | Evidence rule | Confidence |
| --- | --- | --- |
| URL and API references | Static URLs in recognized `fetch`, Axios, or `XMLHttpRequest.open` calls | High; medium for normalized template expressions |
| HTTP method | Explicit `fetch` option, Axios shorthand/config, or XHR `open` method | High |
| Dynamic URL template | Literal template interpolation or direct literal-plus-variable concatenation | Medium; unresolved segments are `{parameter}` |
| Parameters | Static query keys, JSON serialization object keys, `URLSearchParams` keys, or `FormData.append` names | High when attached to a recognized request; medium when unbound |
| WebSocket | `new WebSocket` with a static `ws://` or `wss://` value | High |
| GraphQL | Static `query` or `mutation` operation name | High |
| Client route | Static `path` configuration value | High when structurally represented |
| Source map | Local `sourceMappingURL` comment or explicit local JSON map | High |
| Technology | Paired structural framework/bundler indicators, or a concrete Axios/jQuery API call | High |
| Client source/sink | Recognized APIs such as `location`, `document.cookie`, `innerHTML`, `eval`, or `Function` | High |

Potentially sensitive names such as `token`, `password`, `secret`, or `csrf` are emitted only as `sensitive_parameter_reference`. Values, source-file bodies, cookies, headers, tokens, mappings, and source-map source paths are not persisted.

## Evidence and known limitations

R6 uses the existing `WebAsset`, `Endpoint`, `Parameter`, and append-only `Observation` records. Its `client_side` observation type carries source names such as `jsanalysis.url`, `jsanalysis.api`, `jsanalysis.parameter`, `jsanalysis.websocket`, `jsanalysis.route`, `jsanalysis.sourcemap`, `jsanalysis.technology`, `jsanalysis.client_source`, and `jsanalysis.client_sink`. Static request references are resolved only in memory against the selected asset URL; they are never requested.

This is intentionally conservative. The analysis does not execute expressions, resolve variables across scopes, inspect a runtime router, fetch source maps, parse YAML, process TypeScript-specific syntax beyond what the selected parser accepts, introspect GraphQL, claim a vulnerability, or perform security testing. Minified and bundled JavaScript can yield useful structural signals but may also yield false positives or omit information that only a runtime could reveal.
