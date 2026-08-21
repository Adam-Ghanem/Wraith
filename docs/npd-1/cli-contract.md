# NPD-1 CLI Contract

```text
wraith pentest ports scan TARGET \
  --project PROJECT \
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
  [--campaign ID] \
  [--dry-run] [--json]
```

`custom` requires `--ports`; other profiles reject an explicit port specification. All port input is parsed by the bounded NPD parser.

`--dry-run` returns a deterministic plan and explicitly reports zero network attempts.
