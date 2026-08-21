# T7 Release Security Contract

T7 may be released only when the classification authority remains pure, the additive migration is present, governed observation writes and audit events are atomic, finding and report boundaries fail closed, the legacy fixture-export denial remains in place, and the deterministic T7 guard passes.

| Required release gate | Expected outcome |
|---|---|
| `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...`, `go build ./...` | Clean formatting, static analysis, lint, and build. |
| `go test ./...` and `go test -race ./...` | Full functional and concurrency suite passes. |
| T7 package tests, fuzz smoke test, and benchmarks | Deterministic classification, redaction, audit, and bounds are exercised. |
| Dependency, secret-marker, T4, T5, T6, and T7 scripts | Existing supply-chain/security boundaries and T7 source invariants pass together. |
| Locked web checks and production dependency audit | The unchanged local dashboard remains buildable and dependency-reviewed. |
| `git diff --check` and staged-diff check | No whitespace or staging anomalies. |

No release action in this phase merges the branch to `main`, modifies `main`, enables fixture export, creates T8, or grants a bypass for raw secret persistence.
