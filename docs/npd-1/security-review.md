# NPD-1 Security Review

## Transport ownership

A source audit of the NPD implementation found no new `net.Dial`, raw socket, resolver, subprocess, Nmap or Nuclei execution path. TCP I/O remains owned by `internal/httpengine` R3.

## Authorization

`--authorized` is only an operator acknowledgement. Active execution requires persisted T1 authorization, T2 scope evaluation, T3 classification, a bound T4 trust context, T5 capability authorization and the existing R3 policy checks.

## Resource controls

The bounded parser caps the port set at 4096. Every active NPD probe consumes the existing R10.5 request budget and uses the shared concurrency/rate controllers. Cancellation and task deadlines propagate through the adapter into R3.

## Secrets

Targets containing credentials are rejected by the existing policy/trust validation. Evidence contains only bounded port metadata, references and timestamps; no credentials, tokens or raw transport payloads are stored.

## Dry-run

Dry-run uses the assessment execution engine's planning path. It does not dispatch an adapter, consume request budget, call R3, or create evidence.
