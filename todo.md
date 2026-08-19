- [x] Create `phase-6-hardening-ci` from current main and inventory version, dependency, release, and documentation state.
- [x] Add fully pinned GitHub CI checks for Go and the static dashboard, including dependency-review enforcement.
- [x] Add reproducible release targets, checksum generation, and accurate unsigned-release documentation.
- [x] Produce a complete dependency and license review with an enforced update check.
- [x] Update responsible-use, threat-model, support, privilege, and disclosure documentation without fabricating claims.
- [x] Run local quality gates, validate workflow syntax and scope.
- [x] Commit and push Phase 6.
- [x] Complete GitHub authorization with `workflow` scope and push the branch.
- [x] Observe the actual GitHub Actions result and report whether CI ran and passed (run 32073773616 on commit 92773ff passed).
- [x] Implement R1 Policy Core: project-scoped, deterministic, fail-closed authorization with normalization, deny precedence, expiry/revocation, SQLite persistence, outbound gateway seam, and security test coverage; no scanner changes.
- [x] Implement R2 Web Evidence / Asset Model: project-scoped canonical assets and immutable observations with SQLite persistence, repository contracts, migration compatibility, fuzzing, benchmarks, and no network engine or scanner expansion.
- [x] Implement R3 Unified HTTP Engine: policy-aware, destination-safe bounded HTTP(S) transport with controlled resolution/dialing, redirect reauthorization, R2 observation emission, project-aware CLI validation, and local fixture coverage; stop before R4.
- [x] Complete R3 hardening: persistent transport lifecycle, bounded rate/retry/proxy contracts, reviewed legacy collector migration decisions, completion tests, benchmarks, fuzzing, and security review; do not start R4.
- [x] Finish R3 proxy integration and migrate target-web collectors through the approved shared-engine boundary; document provider and subprocess exceptions separately.
- [x] Establish `feature/r4-web-crawler` from completed R3 and record the R4 crawler contract without starting R5.
- [x] Implement a bounded R3-backed crawler frontier, R2 canonical URL reuse, scope filtering, and project-aware evidence handling.
- [x] Add safe HTML, form, script, API-reference, robots, sitemap, security.txt, redirect, and static-resource discovery without submissions, fuzzing, or vulnerability checks.
- [x] Add localhost-only R4 tests, fuzzing, benchmarks, documentation, quality review, and feature-branch push; do not merge to `main`.
- [x] Create `feature/r5-endpoint-intelligence` from completed R4 and document a passive, bounded R5 specification; do not start R6.
- [x] Implement deterministic project-scoped endpoint, method, parameter, form, API-reference, OpenAPI/Swagger, and GraphQL inventory from existing R2/R4 evidence with zero passive-analysis network I/O.
- [x] Add `wraith endpoints` output, local tests, fuzzing, benchmarks, project-isolation/resource-limit checks, documentation, quality review, and feature-branch push; do not merge to `main`.
- [x] Audit the completed R5 baseline, existing JavaScript analysis, R2 evidence contracts, R4 crawler output, and parser dependency options; create `feature/r6-js-intelligence` without modifying `main`.
- [x] Implement a bounded, deterministic, static-only, zero-network JavaScript intelligence pipeline with project-scoped R2 evidence correlation, local-file/source-map support, and no JavaScript or subprocess execution.
- [x] Add `wraith js` output; test fixtures, isolation, malformed-input and resource-limit coverage, bounded fuzzing and benchmarks; update R6 documentation, complete quality and egress review, commit and push the feature branch. R7 remains separately scoped and unstarted.
- [x] Audit the R1 policy, R2 evidence, R3 transport, R5 inventory, and R6 client-intelligence seams; finalize the bounded R7 controlled-fuzzing specification on `feature/r7-controlled-fuzzing` without modifying `main`.
- [x] Implement deterministic explicit-target plans, generic bounded mutation profiles, request-template transformations, safe-method policy, workload limits, R1 authorization, and R3-only execution with cancellation and local job states.
- [x] Add response fingerprints, baseline comparison, reflection/error/timing metadata, value-redacted R2 fuzz observations, and the explicit-target `wraith fuzz` CLI with heavily tested dry-run output.
- [x] Add project-isolation, authorization, redirect/destination, sensitive-header, size, request-explosion, cancellation, localhost integration, fuzz, benchmark, egress-review, documentation, quality-gate, commit, and push coverage; stop before R8.
- [x] Create `feature/r7.5-content-discovery` from R7 and implement bounded local wordlist path and virtual-host discovery through R1/R3 only: project-local base evidence, soft-404 fingerprints, depth-capped non-crawling recursion, R2 content observations, tests, and no main or R8 changes.
- [x] Create `feature/r8-security-validation` from R7.5 and implement evidence-led, reproducible, R1/R3-only passive security validation with explicit endpoint selection, redacted validation evidence, migration compatibility, fuzzing, benchmarks, and no credential attacks, destructive testing, alternate transport, or main changes.
- [x] Create `feature/r9-vulnerability-intelligence` from the reconciled main branch and implement a SQLite-compatible project-scoped graph schema, deterministic deduplication/correlation, explainable confidence, change detection, local CLI, fuzzing, and benchmarks without Neo4j, remote intelligence, fabricated findings, or main changes.
- [x] R10 implemented on `feature/r10-authenticated-security`; stop after R10.
- [x] R10.5: audit R1–R10 integration seams, then implement a bounded R1/R3-only pentest orchestrator on `feature/r10.5-pentest-orchestrator`; keep main untouched and stop before R11.
- [x] After R10.5 quality gates pass, merge the approved feature branch into `main`; verify R10.5 is present and do not start R11.
- [x] Create `feature/r11.1-request-mutation` from `main` and implement only a deterministic, bounded, no-network Request Mutation Engine that reuses R2/R5/R6/R10/R10.5 data contracts; add tests, fuzzing, benchmarks, documentation, quality review, commit, and push. Stop and await approval before R11.2.
- [x] Create `feature/r11.2-smart-discovery` from R11.1 and implement only bounded, deterministic, project-scoped content and parameter discovery with provenance, R1/R3-only explicit verification, R2 evidence, tests, fuzzing, benchmarks, documentation, security review, commit, and push. Stop and await approval before R11.3.
- [x] Create `feature/r11.3-injection-testing` from R11.2 and implement only a bounded, evidence-driven injection testing engine with R11.1 variants, R1/R3-only explicit execution, R2 signals, R8 validation handoff, R9 correlation handoff, tests, fuzzing, benchmarks, documentation, security review, commit, and push. Stop and await approval before R11.4.

- [x] Create `feature/r11.4-finding-validation` from R11.3 and implement only bounded, project-scoped signal validation and evidence correlation that reuses R1/R3, R2, R8, R9, R10, R10.5, and R11.3; add tests, fuzzing, benchmarks, documentation, security review, commit, and push. Stop and await approval before R11.5.

- [x] After R11.4 is completed and pushed, create `feature/r11.5-risk-intelligence` from its exact completed commit and implement only deterministic, project-scoped risk intelligence over validated R11.4 and correlated R9 evidence; add tests, fuzzing, benchmarks, documentation, security review, commit, and push. Do not merge main or start R11.6/R12.

- [x] Create `feature/r11.6-attack-surface-intelligence` from the completed R11.5 commit and implement only a deterministic, project-scoped attack-surface graph and campaign intelligence layer over existing evidence, relationships, findings, and risk; add tests, fuzzing, benchmarks, documentation, security review, commit, and push. Do not merge main or start R12.

- [x] Create `feature/r12-integration-hardening` from the completed R11.6 commit; audit actual R1–R11.6 state; add deterministic localhost-only/temporary-SQLite CLI smoke infrastructure, bounded integration coverage, stricter production configuration and CLI validation, CI regression protection, release-operational documentation, tests, security review, commit, and push. Do not merge `main` or start R13.

- [x] Create `feature/r13-active-assessment` from the completed R12 commit; audit actual R1–R12 execution seams; implement only a bounded, resumable active assessment execution layer that reuses R1, R3, R10.5, R11.x, and R12 controls; add scope snapshots, deterministic tasks, tests, docs, security review, commit, and push. Do not merge `main` or start R14.
