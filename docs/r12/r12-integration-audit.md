# R12 Integration Smoke Tests and Production Hardening Audit

**Verified base:** `0862694` on `feature/r11.6-attack-surface-intelligence`. R12 work begins on `feature/r12-integration-hardening`; `main` remains at `42cb8b2` and is not modified.

R12 is a test, validation, CI, and release-operational hardening phase. It does not introduce a scanner, attack engine, deployment platform, cloud service, API backend, external integration, worker, or changed exploitation behavior.

| Area | Current verified state | R12 gap / decision |
| --- | --- | --- |
| CLI surface | The dispatcher exposes discover/scan/http/crawl/endpoints/js/fuzz/content/vhost/validate/intelligence/identity/auth-test/compare/pentest/inject/findings/risk/surface/campaign/history/export-fixtures/version, with some subcommands. | Build a source-derived command matrix and test safe plan/dry-run/local read paths. Do not invent missing commands or alter output contracts. |
| R1–R3 boundary | R1 policy and R3 HTTP engine already centralize authorization and transport; existing production occurrences of `http.Client`, `net.Dial`, DNS resolution, and subprocess support are in established subsystem packages. | Add an egress regression inventory; R12 creates no new direct network/process path. |
| Existing tests | Unit tests exist across the repository, including CLI dry-run/integration-style tests and localhost `httptest` fixture usage. | Add a reusable temporary filesystem/SQLite/isolated-project CLI smoke harness and a bounded localhost E2E fixture only for currently exposed interfaces. |
| Persistence | Embedded sequential SQLite migrations are at schema version 14, with existing migration/restart tests. | Add an R12 smoke assertion for clean migration, reopen, and version consistency; do not rewrite historical migrations. |
| Configuration | Individual command parsers validate their own flags, limits, paths, profiles, and durations. | Document and add regression tests for shared fail-closed rejection of malformed project IDs/unsafe numeric bounds where an existing parser is inconsistent. Do not silently alter valid behavior. |
| CI | Pinned-action CI runs module verification, formatting, vet, tests, race, lint, build, dependency-review script, frozen web install, web checks/tests/build, and production web dependency audit. | Add `git diff --check`, migration/smoke coverage, and a non-suppressed R12 integration test target only if the local suite demonstrates stable coverage. Preserve existing workflow checks. |
| Release operations | Release process, support matrix, dependency review, threat model, and responsible-use documents exist. | Add R12 release checklist, operations guide, security hardening document, actual CLI inventory, and compatibility/limitations notes. |

## Actual command inventory and network posture

| Command family | Primary purpose | Typical safety requirement | R12 smoke posture |
| --- | --- | --- | --- |
| `discover`, `scan`, `http`, `crawl`, `content`, `vhost`, `fuzz`, `js` | Existing discovery/probing/crawl/fuzz/content and JS workflows. | Explicit authorization where active; existing R1/R3 path; bounded options. | Parser/dry-run/local fixture only; no external target. |
| `endpoints`, `intelligence`, `findings`, `risk`, `surface`, `history` | Local SQLite evidence/intelligence views. | Project-scoped local database input. | Temporary SQLite and cross-project isolation. |
| `validate`, `inject`, `discover plan`, `pentest plan`, `campaign plan` | Bounded plan/dry-run surfaces. | Explicit authorization; active execution remains behind existing library boundaries. | Assert dry-run is zero-I/O and deterministic. |
| `identity`, `auth-test`, `compare` | Existing R10 identity/auth-security workflows. | Existing authorization/attack gates; no real credentials. | Parser/dry-run and secret-free behavior only. |
| `pentest list`, `pentest resume` | Existing R10.5 lifecycle views/resume. | Project-scoped state and authorization. | Temporary SQLite lifecycle/resume isolation. |

## Configuration, release, and test risks

Configuration parsing is decentralized, so R12 must avoid replacing individual parser semantics with a duplicate configuration engine. The highest-value regression coverage is shared: malformed project identifiers, zero/negative or oversized limits, invalid durations/rates/concurrency, unsafe paths, and impossible profile/module combinations already rejected by each command’s existing boundary. Compatibility changes require an explicit test and documentation.

The release risk is process drift: local quality commands can diverge from CI or from the release checklist. R12 will align documentation and CI with the existing Go 1.23 and pinned pnpm workflow, add no extra Go-version matrix, and ensure required checks are not masked by permissive shell fallbacks. Release guidance will explicitly retain local SQLite backup, redaction, authorization, and bounded-operation limits.

## R12 implementation plan

R12 will add a compact `internal/cli` smoke harness and fixture tests, no production transport. It will exercise existing R1/R2/R5/R8/R9/R10.5/R11.1–R11.6 boundaries through public CLI or stable library seams with temporary SQLite and localhost-only fixtures. Any architecture gap that cannot be tested without a rewrite will be documented as an integration limitation rather than bridged with a bypass.
