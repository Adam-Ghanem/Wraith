# R3 Completion Review

## Legacy collector migration matrix

| Collector | Network I/O | Current transport | R3 decision | Reason |
| --- | ---: | --- | --- | --- |
| `internal/probe` | Yes | Direct `net/http` | Needs architectural adapter | It must retain Phase 2 probe output and retry semantics while gaining an explicit R1 project context. |
| `internal/contentdiscovery` | Yes | Direct `net/http` | Needs architectural adapter | Its baseline comparison and path-discovery semantics require a reviewed R3 adapter rather than a blind replacement. |
| `internal/jsanalysis` | Yes | Direct `net/http` | Needs architectural adapter | It must preserve same-origin script restrictions and redaction behavior. |
| `internal/enum` CRT/VT sources | Yes | Direct `net/http` | Intentionally standalone pending provider review | These are external provider calls, not target-web transport; provider credentials and terms need their own R3 adapter decision. |
| `internal/discovery` / `internal/ports` | No HTTP | Raw local network sockets | Intentionally standalone | Local-network Phase 1 uses a distinct explicit CIDR boundary. |
| `internal/portscan` / `internal/vulncheck` | Optional subprocess | External binaries | Intentionally standalone | They need a separate policy-aware command-adapter design; R3 does not silently alter tool execution. |

The matrix confirms that no legacy target-web collector is yet migrated. R3 is therefore not complete until each target-web adapter has an explicit project/scope input and preserves its documented behavior through the shared engine.
