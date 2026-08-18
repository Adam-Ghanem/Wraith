# R10 — Authenticated Security Boundary

R10 adds a narrowly controlled local identity and authentication-analysis foundation. It does not create unrestricted credential attacks or bypass existing authorization and transport controls.

## Absolute boundary

Every network action, including an authentication attempt, must pass R1 and the shared R3 HTTP engine. R10 must not instantiate an HTTP client, resolve DNS, open sockets, dial targets, bypass redirect validation, or bypass R3 rate/concurrency/response-size controls.

## Explicit operator gates

Normal authenticated analysis requires explicit `--authorized`. Any mode that performs credential attempts—brute force, password spray, credential-list testing, username enumeration, rate-limit testing, or lockout testing—requires **both** `--authorized` and `--attack-auth`. A missing `--attack-auth` must fail before file reads, scheduler creation, DNS, or network I/O. Dry-run must not authenticate or send any request.

## Identity and session models

An `IdentityContext` is project-scoped and records only an ID, name, role label, description, status, and timestamps. A role label does not imply permissions. A `SessionContext` is project-scoped and records identity linkage, status, creation/expiry times, and bounded non-secret metadata. Session material and credentials remain ephemeral runtime-only values and are never persisted.

## Secret redaction

Plaintext passwords, user names paired with passwords, cookies, bearer tokens, API keys, authorization headers, and session tokens must never appear in SQLite, JSON, reports, logs, errors, observations, panic values, benchmarks, tests, or Git. Inputs are represented externally by a `CredentialID` or count only. Central redaction rejects sensitive key names and removes secret-like values from metadata before persistence or output.

## Bounded authentication analysis

R10 begins with deterministic local configuration, bounded local credential-list parsing, response classification, lockout/MFA/CAPTCHA detection, and an attack scheduler contract. The scheduler must enforce global attempts, per-identity attempts, rate, concurrency, cooldown, duration, cancellation, and stop conditions. It must stop an affected identity after lockout, CAPTCHA, or a human-action MFA challenge, and must never increase intensity automatically.

## Evidence and integration

Authentication results store only project ID, identity ID, endpoint identity, method, status class, bounded fingerprint, duration, and redacted observation references. Differential authorization comparisons may compare explicit selected identities and endpoints, but they must never enumerate arbitrary object IDs or automatically classify a response difference as a vulnerability. R8 validates potential candidates and R9 correlates them; R10 never bypasses either layer.

## Exclusions

R10 excludes secret persistence, token or cookie disclosure, MFA/CAPTCHA bypass, OTP guessing, automatic object-ID enumeration, unauthorised testing, remote credential downloads, background scheduling, R11 orchestration, exploit execution, compromise claims, and direct network transports.
