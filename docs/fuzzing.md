# Controlled Fuzzing

## Scope

`wraith fuzz` is a local, bounded, explicitly targeted **generic parameter mutation** workflow. It plans and sends only the operator-selected R2 endpoint and parameter under the named project. It records response intelligence as redacted R2 `fuzz` observations. It does not enumerate content, execute payloads, claim vulnerabilities, score risk, test credentials, upload files, or perform destructive actions.

## Authorization and transport

The command requires `--project` and `--authorized`. A selected endpoint and parameter must exist in that project; an identity from another project is rejected. Non-dry-run requests use only the existing R3 engine, which invokes R1 authorization for the initial target, each redirect, and resolved destination. R7 does not create an HTTP client, resolver, socket, dialer, redirect handler, or proxy path.

R3 continues to enforce destination safety, redirect reauthorization, response bounds, retry rules, request timeouts, transport pacing, and connection limits. R7 adds a bounded local work plan and cancellation-aware worker pool; it does not bypass or replace R3 controls.

## Usage

```text
wraith fuzz \
  --project PROJECT \
  --authorized \
  --endpoint "GET https://target.example/api/users" \
  --parameter id \
  --location query \
  --profile minimal \
  --dry-run --json
```

`--dry-run` emits the deterministic plan, target, mutation IDs/categories, estimate, and limits without constructing or calling R3. R7 supports `query`, `path`, `json`, `form`, and non-sensitive `header` locations. JSON and form targets require an explicit bounded local `--body-file`; request values are not recovered from R2 or persisted.

## Profiles and limits

| Profile | Generic bounded content |
| --- | --- |
| `minimal` | Empty, one-character, and zero values. |
| `boundary` | Fixed small/large numeric and short/medium/bounded string boundaries. |
| `encoding` | Fixed URL, double-encoding, Unicode, whitespace, and reserved-character variants. |
| `type` | Fixed string, integer, boolean, null, empty-array, and single-item-array values. |
| `combined` | Deterministic bounded union of the preceding profiles. |

R7 caps mutation bytes, body bytes, JSON depth, mutation count, total requests, timeout, duration, and workload concurrency. GET, HEAD, and OPTIONS are the default safe methods. POST, PUT, PATCH, and DELETE require both `--allow-unsafe-methods` and `--confirm-unsafe-methods`; R3 does not replay unsafe methods by default.

Sensitive headers including Authorization, Cookie, Set-Cookie, Proxy-Authorization, API-key variants, and token variants cannot be selected or supplied to R7 mutation planning.

## Response intelligence and evidence

An optional single baseline goes through R3 before mutation. R7 compares status, content type, bounded response length, a normalized deterministic fingerprint, reflection location, generic error classes, redirect count, and normal elapsed duration. Reflection is an observation only; it is not an XSS claim. Generic server, validation, parser, database, stack-trace, and type-error indicators are likewise not findings.

Each analyzed result becomes a project-scoped, append-only, redacted R2 `fuzz` observation linked to the canonical endpoint. The persisted data contains mutation ID/category/safety class, response structure, fingerprint, baseline deltas, reflection location, generic error classes, and redirect count. It never contains mutation values, request bodies, response bodies, cookies, Authorization values, tokens, passwords, or API keys.

## Known limitations

R7 is intentionally synchronous and local; jobs are in memory and cannot resume. It accepts only explicit endpoint/parameter selections and does not discover new content or routes. It does not create findings, validate vulnerabilities, classify reflection as XSS, perform authentication/credential testing, fuzz authentication material, perform timing attacks, or expand scope. These boundaries remain deliberate until separately reviewed phases.
