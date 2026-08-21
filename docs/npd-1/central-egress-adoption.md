# NPD-1 Central Outbound Adoption

NPD-1 uses the existing Wraith security architecture for every TCP probe.

## Execution path

```text
operator acknowledgement
        ↓
T1 authorization
        ↓
T2 scope + per-port authorization
        ↓
T3/T4 trust
        ↓
T7 governance / T8 protection
        ↓
R14 campaign + cycle
        ↓
R10.5 budget / concurrency / rate
        ↓
T5 outbound capability authorization
        ↓
T6 central TCP egress dispatcher
        ↓
R3 TCP transport
        ↓
OS routing table
        ↓
authorized target
```

`internal/egress` owns the T6 dispatch boundary only. It does not create sockets,
resolve DNS, invoke subprocesses, or manipulate routes. R3 remains the owner of
TCP connection lifecycle and normal OS routing.

## Routed targets

`wraith pentest ports scan` does not require the destination to belong to the
local interface CIDR. A routed target is eligible when the authoritative
authorization/scope/trust/budget/egress checks permit it. The R3 transport then
uses the host operating system's normal routing behavior.

Local `wraith discover` retains its existing local-interface/CIDR semantics;
it is not silently converted into a routed TCP scanner.

## CLI

Use the NPD command for controlled TCP discovery:

```bash
wraith pentest ports scan 192.168.1.254 \
  --project lab \
  --campaign local-lab \
  --authorized \
  --scope-version 1 \
  --profile custom \
  --ports 22,80,443
```

`--authorized` is an operator acknowledgement. It does not replace T1/T2
authorization, T3/T4 trust, T7/T8 controls, R14 lifecycle, R10.5 budgets, T5,
or T6.

The legacy `wraith scan` command remains a separate Phase-2 web/provider path.
Its outbound block is intentionally preserved until that legacy capability has
its own audited central adoption. `wraith scan --help` remains available
without executing the block or performing any network I/O.

## Fail-closed rule

An individual port must pass T2 authorization and the T5/T6/R3 chain before a
TCP attempt can occur. Unauthorized ports never reach the transport.
