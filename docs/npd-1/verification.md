# NPD-1 Verification and Regression

NPD observations remain ordinary R2/T8 evidence and retain project, scope, authorization, task and observation lineage. R16/R18 consume the existing projections rather than a parallel NPD reporting store.

## Deterministic gates

- port parser unit tests cover malformed input, duplicates, overlaps, bounds and deterministic ordering;
- shared TCP target normalization tests cover host, IPv4, IPv6, explicit ports, credentials and malformed authorities;
- scanner tests prove policy failures are not classified as `closed` and cancellation prevents additional R3 calls;
- NPD fuzz smoke covers bounded port parsing, TCP target normalization and no-network planning;
- NPD benchmarks cover parsing, canonical ordering, target normalization and task planning;
- CI runs each fuzz target for a fixed 10-second smoke window and runs offline benchmarks with a fixed 1-second benchmark window.

## Campaign/replay

NPD execution requires a persisted R14 campaign whose canonical stored plan matches the requested project, scope, target, profile and effective ports. R14 creates the cycle, selects eligible tasks from the latest checkpoint, and rejects a completed NPD task from silent replay.

## Regression

`internal/npd/regression.go` projects each canonical port/state into the existing R18 snapshot `EndpointIDs` representation. This deliberately reuses R18 rather than creating a second comparison engine. A state transition therefore appears as a deterministic removal/addition of the corresponding port-state surface identity.

A missing observation is not converted to `closed`; incomplete, blocked or cancelled scans remain incomplete in the assessment lifecycle.
