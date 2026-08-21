# NPD-1 CLI Contract

```text
wraith pentest ports scan TARGET \
  --project PROJECT \
  --campaign CAMPAIGN \
  --authorized \
  --scope-version VERSION \
  --profile safe|standard|deep|custom \
  [--ports 22,80,443] \
  [--db wraith.db] \
  [--timeout 10s] \
  [--max-ports N] \
  [--max-requests N] \
  [--max-concurrency N] \
  [--rate N] \
  [--dry-run] [--json]
```

`TARGET` must be an explicit canonical TCP host target such as `tcp://example.test` or `tcp://10.0.0.5`. A port on `TARGET` is rejected by the scan command because the requested port set is supplied separately.

TCP targets are normalized by the shared policy parser. Credentials, unsupported schemes, malformed authorities, invalid ports, path/query/fragment data and ambiguous authorities are rejected. HTTP/HTTPS parsing remains unchanged.

`--campaign` is mandatory for active NPD execution. The supplied ID must resolve to a persisted R14 campaign in the selected project, be `ready`, and contain the exact canonical NPD task plan. The caller cannot create campaign authority by placing an arbitrary ID in the trust context.

`--authorized` is only an operator acknowledgement. T1 authorization and T2 scope remain authoritative.

`custom` requires `--ports`; other profiles reject an explicit port specification. All port input is parsed by the bounded NPD parser and capped at 4096 effective unique ports.

For every requested port, NPD constructs a canonical `tcp://HOST:PORT` destination and re-evaluates T2 before T5/R3. Unauthorized ports are recorded as authorization/policy outcomes and never reach R3.

`--dry-run` performs parsing, campaign validation and authorization planning only. It does not dispatch the adapter, call T5/R3, consume the active network budget, create checkpoints, or persist evidence.
