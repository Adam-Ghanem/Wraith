# NPD-1 Architecture

NPD-1 is a bounded TCP reachability capability. It does not own sockets and does not invoke Nmap or another subprocess.

## Execution boundary

```text
NPD plan/adapter
    -> existing R13 execution engine
    -> existing trust/scope/authorization gates
    -> R3 TCPClient
    -> existing R3 policy gateway + resolver/destination controls
    -> TCP connection attempt
```

The new `internal/httpengine.TCPClient` is an extension of the existing R3 transport owner. NPD calls `ProbeTCP`; it never receives a socket.

## Bounds

- TCP only
- maximum 4096 explicit ports per scan
- deterministic ascending port order
- `safe`: 22, 80, 443
- `standard`: conservative common-service set
- `deep`: ports 1-1024
- custom port expressions are parsed and bounded
- no UDP, SYN crafting, packet fragmentation, service exploitation, banner grabbing, or vulnerability execution

## Port state

- `open`: R3 successfully establishes a TCP connection
- `closed`: R3 reports an explicit connection refusal
- `filtered`: timeout/deadline without a definitive refusal
- `authorization_denied`: authorization/scope failure
- `budget_exhausted`: shared budget/rate control failure
- `policy_denied`: outbound policy or destination control denied the attempt
- `transport_error`: unexpected R3 transport failure

Security-control failures are never converted to `closed`.

## Legacy boundary

The pre-existing `internal/probe/tcp.go` and `internal/portscan` implementations are legacy paths. NPD-1 does not call either one. In particular, NPD-1 does not invoke the existing Nmap subprocess path.

T6 currently remains a CLI compatibility/enforcement boundary rather than a standalone `internal/egress` transport package. NPD must not invent a second T6 implementation.
