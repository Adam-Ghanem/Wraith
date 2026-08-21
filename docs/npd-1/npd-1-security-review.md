# NPD-1 Security Review

## Controls preserved

- NPD owns no network sockets, resolver, HTTP client, or subprocess.
- R14 owns campaign/cycle/task lifecycle and replay protection.
- T1 authorization is loaded from the persisted lifecycle; `--authorized` is not authoritative.
- T2 is authoritative for every actual TCP destination, not only the host-level plan.
- T3/T4 trust is freshly derived for the exact task and bound to project, scope, assessment and campaign.
- T5 capability authorization is required immediately before R3 delegation.
- R10.5 request budget, concurrency and rate controls remain shared controls.
- R3 remains the only TCP transport owner.
- R2/T8 observations contain bounded metadata and existing lineage references only.

## TCP target security

The shared policy parser now accepts explicit `tcp://` targets while preserving HTTP/HTTPS semantics. TCP targets reject credentials, unsupported schemes, invalid ports, ambiguous authorities and path/query/fragment data. A scan target is host-level and every probe is normalized to `tcp://HOST:PORT` before T2 evaluation.

## Multi-port authorization

A host-level TCP target is never treated as wildcard permission. NPD re-loads the current T2 scope and T1 authorization for each probe. An unauthorized port produces a typed policy/authorization result and the R3 transport is not called. If the requested set has no currently authorized port, execution fails closed before adapter dispatch.

## Dry run

R14's dry-run path returns a plan without dispatching the adapter. Therefore NPD dry-run performs zero T5/R3 operations, zero network attempts, zero evidence writes and zero execution checkpoints.

## Static boundary

The existing T6 guard explicitly rejects transport/resolver/subprocess primitives in `internal/npd`. The NPD adapter delegates through the injected R3 `TCPClient`; it does not add a second transport stack.

## Non-goals

NPD-1 does not identify services, versions, operating systems, vulnerabilities, exploitability, credentials, banners, or arbitrary response bodies.
