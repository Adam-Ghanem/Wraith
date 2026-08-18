# R7.5 — Bounded Content and Virtual-Host Discovery

R7.5 provides two narrowly scoped, operator-initiated discovery commands: `wraith content` for local wordlist path checks and `wraith vhost` for local virtual-host label checks. Both commands create **observations only**. They do not claim vulnerabilities, severity, confidence, exploitability, or findings.

## Preconditions and safety boundary

Use these commands only for systems you own or are explicitly authorized to assess. Each run requires `--authorized`, an explicit `--project`, and a base URL that already exists in the selected project's R2 evidence. A URL observed solely in another project is rejected. The wordlist must be an explicit local regular file; Wraith never downloads a wordlist.

Every baseline and candidate request uses the shared R3 HTTP transport. R3 evaluates R1 policy before resolution and connection, rechecks redirects and resolved destinations, applies the configured rate and concurrency limits, and keeps response bodies bounded. R7.5 creates no alternate HTTP client, DNS resolver, socket, dialer, browser, subprocess, remote API, or external tool path.

## Path discovery

```bash
./bin/wraith content \
  --project project-a \
  --authorized \
  --db wraith.db \
  --base-url https://app.example.test/ \
  --wordlist ./wordlists/paths.txt \
  --max-entries 200 \
  --max-requests 201 \
  --max-duration 1m \
  --concurrency 2 \
  --rate 5 \
  --depth 0
```

The command normalizes relative local path entries, rejects traversal, schemes, query/fragment components, control characters, duplicate entries, oversized lines, and oversized files. It first fetches a fixed reserved baseline path through R3. Candidate responses that match that baseline by status, content class, normalized fingerprint, and bounded length are treated as soft-404 responses and are not reported.

`--depth` defaults to `0` and is capped at `2`. A positive depth does **not** turn R7.5 into the R4 crawler: it never parses HTML, follows links, reads robots/sitemaps, or expands externally derived URLs. It merely forms bounded child paths from the same supplied local wordlist below meaningful HTML paths, while retaining the global `--max-requests` ceiling.

## Virtual-host discovery

```bash
./bin/wraith vhost \
  --project project-a \
  --authorized \
  --db wraith.db \
  --base-url https://edge.example.test/ \
  --host-suffix example.test \
  --wordlist ./wordlists/vhost-labels.txt \
  --max-entries 200 \
  --max-requests 201 \
  --max-duration 1m \
  --concurrency 2 \
  --rate 5
```

The vhost wordlist contains hostname labels such as `admin` or `api`. R7.5 forms `admin.example.test` and `api.example.test`, validates each label, and keeps the transport destination fixed at `--base-url`. The shared R3 engine applies the resulting hostname as a validated native HTTP Host override and obtains a separate R1 authorization decision for that candidate host before DNS resolution or network I/O. It does not perform candidate DNS resolution, direct socket connections, or TLS/SNI probing outside R3.

## Evidence and output

Use `--dry-run` to validate the project, base evidence, local wordlist, and bounded plan without issuing requests. Use `--json` for structured output. Meaningful results persist as project-local R2 URL assets and GET endpoints, with an append-only `content_discovery` observation containing only status, content type/class, bounded content length, fingerprint, baseline similarity, redirect count, and duration. Raw response bodies, request values, cookies, authorization material, tokens, and arbitrary headers are not stored.

## Exclusions

R7.5 excludes remote wordlists, arbitrary target expansion, link crawling, sitemap/robots expansion, authentication attacks, credential testing, form submission, JavaScript execution, parameter fuzzing, vulnerability validation, exploitation, destructive testing, and findings. R8 is a separate later phase.
