# T5 Release Security Contract

## Release Preconditions

T5 may be released only when the policy package remains I/O-free, the R15 adapters use the injected gateway, and the gateway continues to fail closed before any R3 delegation. The release applies to the T5 feature branch only; it does not authorize a merge to `main` by itself.

| Required check | Purpose |
|---|---|
| `gofmt -l .` | Preserves Go formatting. |
| `go test ./...` and `go test -race ./...` | Exercises functionality and race safety. |
| `go vet ./...`, `golangci-lint run ./...`, and `go build ./...` | Applies static analysis and build verification. |
| `bash scripts/check-t5-outbound-gateway.sh` | Verifies T5 files, authority calls, R15 seam wiring, offline diagnostic, and prohibited imports. |
| Existing dependency and secret-marker checks | Retains supply-chain and high-confidence secret checks. |
| Web install, check, test, build, and production audit | Retains repository-wide release quality gates. |
| `git diff --check` | Rejects whitespace damage. |

## Change-Control Rules

Adding an outbound operation requires an explicit capability ID, one owner, a required assurance level, a statement of scope and budget binding, updated baseline inventory, unit and negative tests, fuzz coverage where input parsing changes, benchmark review, and a security-review update. No capability may silently make a legacy path governed or exempt.

When the audit store is unavailable, the target is malformed or credential-bearing, T4 validation fails, T2 denies scope, the budget reference mismatches, or a request violates the read-only contract, the correct release behavior is denial and no R3 dispatch.
