# Wraith Phase 3 Implementation

## Scope and authorization

Phase 3 extends an authorized `wraith scan` with bounded content discovery and JavaScript analysis. It does not alter the frozen Phase 1 local-network discovery behavior. It also does not add subdomain port scanning, Nmap, Nuclei, vulnerability correlation, REST APIs, dashboards, PDF/CSV export, scheduling, or multi-tenancy.

The existing `--authorized` parser gate remains mandatory for `scan`. It is a self-attestation only: Wraith does not verify ownership or permission. The operator must confirm ownership, written permission, or an in-scope bug-bounty authorization before running a scan.

## Content discovery

Content discovery uses a finite built-in list of approximately 100 high-value paths. It makes a baseline request to a generated random path on the same host before testing the wordlist. The baseline records status code, response length, and a SHA-256 body fingerprint. A candidate is reported only when its status is 200, 301, 302, or 403 and it differs from the baseline by status, response length, or body fingerprint. This removes common soft-404 pages that return 200 for every path while retaining meaningful redirects and protected resources.

Requests use the existing Phase 2 `enum.RateLimiter`, not a second independent limiter. Each host receives at most 20 request starts per second, content workers are capped at 50, request timeouts are bounded, response bodies are capped at 4 MiB, and redirects are capped at five hops. Redirects to a different hostname are rejected. Invalid, absolute, and parent-directory-escaping paths are rejected before a request is made.

## JavaScript analysis

For each selected live HTTP result, the analyzer fetches the host-root HTML with the same bounded timeout, response-size, retry, and same-host redirect conventions. It parses external `<script src>` tags using the standard library, resolves relative references with `url.ResolveReference`, retains same-host HTTP/HTTPS URLs, removes fragments, and deduplicates them.

JS files are fetched with at most 50 workers, a 20-per-second per-host limiter, a five-second default timeout, one timeout-only retry, same-host redirect enforcement, and a 5 MiB maximum body. Findings are deduplicated per subdomain and capped at 50 total findings. Endpoint extraction is regex-based and conservative; it is not vulnerability analysis.

Potential secret matches include AWS access-key-shaped strings, generic API-key assignments with at least 16 characters, and JWT-shaped strings. Every secret finding is labeled `potential`. The full value is never persisted, logged, or emitted in output. The stored/displayed representation is `first4…last4`, or `REDACTED` for short values. Wraith never validates, uses, or exfiltrates a suspected credential.

## Storage and history

Migration `002_phase3_findings.sql` is append-only and does not alter the Phase 2 migration. It adds `content_findings` and `js_findings`, each linked to a scan with a foreign key and lookup index. Scan persistence is transactional through `SaveScanWithFindings`.

The diff engine reuses the Phase 2 typed snapshot pattern. Phase 3 diffs report only `NEW` content paths and `NEW` JavaScript findings; changes to an existing finding are not reclassified as new. History JSON and terminal output include separate content and JS finding sections.

## CLI

The default scan runs both analyses after Phase 2 HTTP probing. They can be disabled independently:

```bash
./bin/wraith scan -d example.com --authorized --db wraith.db --skip-content-discovery
./bin/wraith scan -d example.com --authorized --db wraith.db --skip-js-analysis
```

The JSON scan output includes `content_findings` and `js_findings`. History output includes `content_changes` and `js_changes`.

## Testing limitations

Unit tests cover baseline comparison, soft-404 filtering, path validation, bounded content concurrency, script URL resolution, endpoint and secret-pattern extraction, redaction, JS deduplication, file/concurrency limits, migration 002, transactional persistence, and NEW-only diffs. Tests use local `httptest` servers and fake resolvers. No real authorized domain, crt.sh response, DNS infrastructure, or VirusTotal account was used for Phase 3 verification. A real authorized integration run remains a separate operator-controlled step and must not be inferred from the passing mocked tests.
