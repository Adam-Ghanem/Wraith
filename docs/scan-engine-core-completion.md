# Scan Engine Core Completion Contract

This document completes the existing Scan Engine Core only. It does not add Host Discovery, service detection, version detection, operating-system detection, or probe plugins.

## Authority and ownership

The Core remains an orchestrator. All TCP I/O stays behind the existing R3-owned `httpengine.TCPClient`; the Core must not open sockets, resolve DNS, or create an alternate transport. Every active scan command must be bound to an active project authorization and matching scope decision before scheduling probes. The standalone allow-all gateway is not an acceptable production authorization path.

## Retry contract

Retries are a per-probe scheduler decision, not a transport replacement. Attempts are bounded by a deterministic maximum, use no background worker or unbounded backoff loop, stop immediately when the context is cancelled or expired, and consume the same timeout, concurrency, rate, and budget controls as the initial probe. Only transient transport failures may be retried; policy, authorization, budget, cancelled, and refused/closed outcomes are final.

## Result contract

Each port produces one stable terminal probe result with target, port, protocol, profile, final state, safe classified failure, total attempt count, duration, and observation time. Raw transport errors, resolved destinations, credentials, or any private implementation details are not exposed.

## Event contract

Events are optional local observer notifications: scan started, probe started, probe completed or failed, scan completed, and scan cancelled. Observation never changes scheduling semantics. Delivery is non-blocking and bounded, and the scan continues if no observer is configured or an observer cannot consume events.

## Completion gate

Core completion requires focused retry/result/event tests, integration tests for cancellation, timeout, failure isolation, worker termination, and R3 authorization behavior, repository formatting and quality gates, and a completed green remote CI run. No subsequent scanner phase starts as part of this work.
