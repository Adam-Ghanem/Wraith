# R3 Unified HTTP Engine

`internal/httpengine` is the new generic HTTP(S) transport boundary for future Wraith modules. It receives an explicit project ID and request, parses the R1 target before any DNS or socket operation, evaluates the existing R1 gateway, resolves through an injected resolver, validates destination addresses, authorizes the pinned address for connection, and dials that validated address directly.

Redirects are manual: every `Location` is parsed, authorized, resolved, destination-validated, and dialed independently. A redirect policy failure is returned as `ErrRedirectDenied`; it does not inherit the first target's allow decision. The default destination policy fails closed for unspecified, loopback, link-local, multicast, private, and CGNAT destinations. `AllowPrivate` is an explicit local/internal-test override and must not be enabled casually.

Responses use bounded reads and retain metadata when a body is truncated. TLS verification remains enabled; TLS 1.2 is the minimum. Request headers are carried in memory only, while R2 observation emission passes response headers through the existing R2 redactor before a sink persists them. The minimal `wraith http TARGET --project PROJECT --authorized` command loads the existing SQLite R1 scope and emits no response body or credentials.

R3 does not yet migrate legacy Phase 1–6 collectors, add crawler/fuzzer/security-check behavior, or provide a global rate limiter, retry policy, proxy-specific validation, or persistent connection pool across separate engine calls. Those integrations require follow-up review before the old direct clients are replaced.
