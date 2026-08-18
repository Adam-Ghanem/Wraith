# R4 Web Crawler

`internal/crawler` is the R4 discovery layer. It accepts a project-scoped start URL and sends every fetch through the injected `httpengine.Client`; it does not create an HTTP client, resolve DNS, dial sockets, or implement authorization. R3 therefore keeps R1 request/connection authorization, controlled resolution, destination validation, redirects, TLS, response bounds, and redacted HTTP observation emission as the active egress boundary.

## Boundaries and defaults

`wraith crawl TARGET --project PROJECT --authorized` uses a bounded configuration: depth two, 100 pages, four R3 in-flight request slots, 20 R3 requests per second, 1 MiB per response, 16 MiB total body bytes, 20 query variants per canonical path, a two-minute total crawl budget, 10-second request timeout, five redirects, same-origin filtering, and robots guidance enabled. Numeric CLI limits are validated before storage or network work begins.

The crawler reuses `evidence.CanonicalizeURL` for every frontier identity. Fragments therefore do not create additional fetches, duplicate canonical URLs are suppressed, and query strings remain discovered URLs rather than inputs for generated combinations. Same-origin filtering prevents ordinary third-party traversal; it is an efficiency guard only. R1 remains the authority for every actual request, redirect, and resolved connection.

## Discovery and evidence

HTML is parsed with `golang.org/x/net/html`, not regular expressions. The parser identifies links, forms, scripts, images and other static resources, base URLs, meta refresh, query parameters, and API-like references. Form actions and parameter **names** can be stored through the existing R2 web-asset, endpoint, and parameter identities; parameter values, cookies, bodies, credentials, and HTML bodies are not persisted by the crawler.

When enabled, robots guidance can supply disallowed paths and sitemap locations; sitemap XML and `/.well-known/security.txt` are fetched only through R3. Robots and security.txt are discovery metadata, never authorization. A sitemap or document link is subject to the same canonical frontier and R3 policy path as any other URL.

## Non-goals

R4 does not submit forms, execute JavaScript, generate parameter combinations, brute-force directories, fuzz endpoints, run vulnerability checks, invoke GraphQL operations, store credential values, or create findings. Provider APIs and optional subprocesses retain their documented R3 exceptions. R5 and later phases are not started by this branch.
