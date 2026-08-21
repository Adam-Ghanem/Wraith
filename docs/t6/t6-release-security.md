# T6 Release Security Contract

T6 is release-eligible only when the source inventory still matches the repository, the root CLI gate blocks audited legacy/provider/subprocess commands, and the existing R15 assessment/campaign path still delegates through T5 before R3. The change is feature-branch-only and is not authority to merge `main` or begin T7.

| Required verification | Purpose |
|---|---|
| `go test ./...` and `go test -race ./...` | Functional, integration, and race regression coverage. |
| Focused T6 unit, fuzz, and benchmark runs | Root denial determinism, no caller-controlled message leakage, and local overhead. |
| `bash scripts/check-t6-central-egress-adoption.sh` | Verifies documents, root gate, typed denials, approved T5 seam, and exact audited CLI R3-constructor set. |
| Existing T4/T5 checks | Preserves prior trust and outbound-gateway constraints. |
| `go vet`, `golangci-lint`, build, dependency, secret, web, and diff checks | Retains the repository’s full release-quality boundary. |

Any new CLI R3 constructor, direct provider client, resolver, socket, subprocess caller, or central gateway capability requires a new source-inventory decision, security review, test, and deterministic CI update. A convenience exception is not permitted.
