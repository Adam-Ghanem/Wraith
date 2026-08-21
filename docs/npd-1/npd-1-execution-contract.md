# NPD-1 Execution Contract

## Dry run

Dry run is planning-only. It parses and canonicalizes ports and validates the supplied target shape. It does not call `TCPClient`, open sockets, send packets, create network evidence, or mutate assessment findings.

## Active execution

Every port is represented as one bounded R3 probe. NPD never retries independently. If the underlying R3 layer rejects the operation, NPD records the explicit security/transport state and does not reinterpret the result.

## Cancellation

Cancellation is checked before each probe. Ports that were not scheduled are not marked closed.

## Determinism

Ports are sorted numerically and duplicate entries are rejected at the plan boundary. JSON fields are stable and secret-minimized.

## Time limits

The requested per-port timeout is passed to R3. R3 caps it against the configured request timeout and the parent context deadline.
