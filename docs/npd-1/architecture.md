# NPD-1 Architecture

NPD-1 is a bounded authorized TCP reachability capability. It is an R13/R15 adapter, not a transport implementation.

Execution path:

`CLI → R14 assessment/campaign task → T1/T2/T3/T4 validation → T5 outbound capability → R10.5 request controls → R3 TCP transport → R2/T8 evidence → R16 output → R17 verification → R18 snapshot projection`.

NPD never owns sockets, DNS resolution, HTTP clients, subprocesses, schedulers, or authorization state.

The adapter revalidates the trusted context and delegates every probe through the existing T5 gateway and injected R3 TCP client. Per-probe budget, concurrency and rate controls are applied in the R3 delegation wrapper.

## Profiles

- `safe`: 22, 80, 443
- `standard`: bounded common TCP service set
- `deep`: ports 1–1024
- `custom`: explicit bounded `--ports` specification

The canonical port order is ascending and duplicate/overlapping ranges are deduplicated before the limit is enforced.
