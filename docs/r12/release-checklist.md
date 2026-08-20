# R12 Release Checklist

This checklist is for a reviewed Wraith release candidate. It does not authorize scanning, deployment, or a merge by itself.

| Check | Required evidence |
| --- | --- |
| Repository and branch | Working tree is clean; intended feature/release branch and exact commit are recorded; `main` merge is separately approved. |
| Go quality | `gofmt -l .` is empty; `go test ./...`, `go test -race ./...`, `go vet ./...`, and `go build ./...` pass. |
| Web quality | `pnpm --dir web check` and `pnpm --dir web test` pass. |
| Migration safety | A clean SQLite database migrates sequentially, reopens, and reports the expected schema version. |
| Smoke and isolation | R12 local CLI smoke, dry-run, authorization, and project-isolation regressions pass. |
| CI and dependency review | Pinned workflow checks, locked web install, module verification, dependency-review coverage, and production web audit pass. |
| Security review | Egress inventory has no unexpected direct transport/process path; no secrets are staged; authorization, redaction, and limits remain intact. |
| Release record | Release notes, known limitations, supported environment, and responsible-use terms are reviewed. |

Before publishing any artifact, verify `make release`, record the commit and checksum, and confirm the generated binary is tested in the target local environment. Wraith does not provide deployment infrastructure through R12.
