# NPD-1 Architecture

NPD-1 is a bounded, authorized TCP reachability capability. It does not own sockets and does not invoke Nmap, Nuclei, a resolver, or another subprocess.

## Execution boundary

```text
CLI
  -> persisted R14 campaign validation
  -> R14 cycle/task selection and replay protection
  -> T1 authorization recheck
  -> T2 host/port scope validation
  -> T3 security-trust classification
  -> T4 task-bound trust context + audit
  -> R15 NPD adapter
  -> per-port T2 revalidation
  -> T5 outbound capability gateway
  -> R10.5 budget/rate/concurrency
  -> R3 TCPClient
  -> TCP connection attempt
  -> R2/T8 evidence
  -> R16/R18 projections
```

The existing `internal/httpengine.TCPClient` remains the R3 transport seam. NPD receives an interface, never a socket, and never owns transport policy.

## Canonical TCP target

NPD uses the shared policy target parser. A scan target is host-level TCP:

- `tcp://example.test`
- `tcp://10.0.0.5`
- `tcp://[2001:db8::5]`

A port-bearing TCP URL is a valid shared target representation, but the NPD scan command rejects it because scan ports are supplied separately. Every actual probe is represented as `tcp://HOST:PORT` for T2 authorization.

Credentials, unsupported schemes, ambiguous authorities and TCP path/query/fragment data are rejected. HTTP/HTTPS target semantics are unchanged.

## Multi-port authorization

The host-level plan is never treated as permission for arbitrary ports. For each effective port:

```text
HOST + PORT
  -> canonical tcp://HOST:PORT
  -> T2 scope evaluation
  -> T3/T4 trust remains bound to the task
  -> T5 gateway
  -> R10.5
  -> R3
```

If T2 rejects a port, the adapter records an explicit policy/authorization outcome and does not call R3 for that port. If all effective ports are unauthorized, the task fails closed before active execution.

## Bounds

- TCP only
- maximum 4096 effective unique ports per scan
- deterministic ascending port order
- `safe`: 22, 80, 443
- `standard`: conservative common-service set
- `deep`: ports 1-1024
- `custom`: explicit bounded port expression
- no UDP, SYN crafting, packet fragmentation, service exploitation, banner grabbing, or vulnerability execution

## Port state

- `open`: R3 successfully establishes a TCP connection
- `closed`: R3 reports an explicit connection refusal
- `filtered`: timeout/deadline without a definitive refusal
- `authorization_denied`: T1/T2/T3/T4 rejection
- `budget_exhausted`: R10.5 request/rate/concurrency denial
- `policy_denied`: T2/T5 destination or policy denial
- `transport_error`: unexpected R3 transport failure

Security-control failures are never converted to `closed`.

## Dry run

Dry run uses the R14 execution engine's no-dispatch path. It performs validation/planning only and does not call the NPD adapter, T5, R3, create checkpoints, consume active network budget, or persist evidence.
