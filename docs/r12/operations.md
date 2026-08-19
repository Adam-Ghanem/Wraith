# R12 Operations Guide

## Installation and local setup

Use Go 1.23 and the repository’s documented module dependencies. Build locally with `make build` or `go build -o bin/wraith ./cmd/wraith`. The web workspace is optional for CLI operation; when used, install its locked dependencies with pnpm and run the documented web checks.

Create or select a project identifier before using project-scoped commands. Most active web and assessment commands require `--authorized`; authorization intent does not expand the existing R1 target policy. Start with plan/dry-run modes whenever a command offers them, then review output, resource limits, and the selected local database path.

| Operational activity | Existing safe interface | Limit |
| --- | --- | --- |
| Local evidence and inventory | `endpoints --project PROJECT --authorized --db PATH`, `intelligence`, `findings`, `risk`, `surface` | Data is project-scoped in SQLite. |
| Planning | `pentest plan ... --dry-run`, `inject plan ... --dry-run`, `campaign plan ... --dry-run` | Plans do not execute active work from the CLI surface. |
| Lifecycle review | `pentest list`, `pentest resume`, `history` | Resume follows existing recorded lifecycle state; it does not invent work. |
| Safe troubleshooting | `version`, parser usage errors, local fixture tests, and database reopen checks | Do not substitute external targets, real credentials, or unreviewed wordlists. |

## Limits, pause/resume, and troubleshooting

Use bounded profiles, durations, concurrency, response sizes, request counts, and rates supplied by each command. A lower value is appropriate when a target is fragile; do not use configuration to bypass hard maxima. Existing pentest lifecycle commands support state inspection/resume where recorded state exists. R12 does not add a scheduler, worker, report server, or background process.

Common failures include missing `--authorized`, project mismatch, invalid local paths, malformed durations, exhausted budgets, policy denial, expired authorization, and SQLite path/permission issues. Address the reported local condition; do not weaken policy or transport checks to continue.

## Local SQLite backup and restore

Stop concurrent local CLI activity before copying a database. Preserve the database file and any application-managed sidecar files together, store backups with least-privilege filesystem permissions, and test restore by copying to a separate temporary location, opening it, migrating it, and running a project-scoped read command. Do not place secrets in database labels, project IDs, findings descriptions, or backup paths.

## Security considerations

Use only assets you own or are explicitly authorized to test. Keep credentials out of command arguments, logs, fixtures, and SQLite content. R12 does not add report rendering or a remote logging service; operational logs remain local to the invoked command and existing test/tooling output.
