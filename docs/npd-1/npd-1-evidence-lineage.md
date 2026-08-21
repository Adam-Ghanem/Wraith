# NPD-1 Evidence Lineage

The intended lineage is:

```text
T1 authorization
  -> T2 scope version
  -> T3/T4 trust context
  -> R13 task
  -> NPD port probe
  -> R3 transport observation
  -> R17 verification
  -> R16/R18 consumers
```

NPD result objects contain project and scope references and safe timing metadata. They do not contain credentials, raw request bodies, banners, private keys, or authorization secrets.

The current scanner core intentionally stops at the R3-backed observation boundary. It does not fabricate an evidence reference when the repository evidence model has not yet been extended with a TCP-port observation type. Adding a fake reference would violate R17 lineage guarantees.
