# T2 Scope CLI

All commands are local and require `--authorized`; none performs DNS, HTTP, sockets, subprocesses, or scanning.

```text
wraith scope create --authorized --project PROJECT --version VERSION --authorization AUTH_ID --allow example.com [--allow '*.example.com'] [--deny admin.example.com] [--json] [--db PATH]
wraith scope list --authorized --project PROJECT [--json] [--db PATH]
wraith scope show --authorized --project PROJECT --version VERSION [--json] [--db PATH]
wraith scope validate --authorized --project PROJECT --version VERSION --authorization AUTH_ID --target https://example.com [--json] [--db PATH]
```

`--allow example.com` is an exact-host rule. `--allow '*.example.com'` is an explicit strict-subdomain rule: it matches `api.example.com`, but not `example.com`, `evil-example.com`, or `example.com.attacker.com`. A matching deny rule always overrides every allow rule.

When no explicit port rule exists, the authority accepts only the default port of the normalized HTTP(S) scheme (`80` for HTTP and `443` for HTTPS). It does not silently authorize a non-default port.

Scope creation requires an existing active T1 authorization whose scope reference exactly equals `--version`. Validation checks the same binding, project identity, expiry, revocation, canonical scope fingerprint, and target membership. A validation failure emits no secrets and performs no network activity.
