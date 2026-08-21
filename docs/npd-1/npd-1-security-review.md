# NPD-1 Security Review

## Controls preserved

- NPD owns no network sockets.
- Active probes are delegated to the R3 `TCPClient` contract.
- R3 performs policy authorization before DNS resolution and dialing.
- Destination validation is reused from the existing R3 safety policy.
- Cancellation and bounded timeouts are propagated through R3.
- NPD rejects malformed and oversized port specifications.
- NPD never reports authorization or policy failures as closed ports.
- No subprocess, Nmap, raw packet, SYN, spoofing, fragmentation, or evasion path exists in NPD.

## Known integration boundary

The repository's T6 implementation is currently a CLI enforcement/compatibility layer, while R3 owns the actual local transport. There is no independent `internal/egress` TCP transport owner to reuse. NPD therefore extends the established R3 owner instead of creating another egress/socket stack.

The full R13/R15/T5 evidence-producing adapter integration is still a required completion gate; the current NPD core deliberately does not fake evidence or bypass those systems.

## Threats addressed

- unauthorized target: denied by R3 policy before I/O
- unauthorized port: denied by the existing scope policy before I/O
- cancellation: no new probe is scheduled after cancellation
- timeout: bounded by the R3 transport
- resource amplification: port count and parser expansion are bounded
- false positive: only successful R3 connection yields `open`
- secret leakage: NPD stores no credentials, request bodies, or raw banners

## Non-goals

NPD-1 does not identify services, versions, operating systems, vulnerabilities, or exploitability.
