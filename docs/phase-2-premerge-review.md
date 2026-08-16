# Wraith Phase 2 Pre-Merge Review

**Branch reviewed:** `phase-2-storage-web-recon`
**Base reviewed:** `main` at `5074cec`
**Branch tip:** `bcbae49`
**Review posture:** Review only. No merge, push, or automatic fixes were performed.

## Executive verdict

The Phase 2 branch is functionally coherent and passes the available automated quality gates, but it is **not ready for merge without addressing the SQLite ignore rule and the authorization wording**. The most concrete blocker is repository hygiene: `.gitignore` does not ignore `wraith.db`, `*.db`, or SQLite sidecar files even though the new CLI writes a database by default. This creates an avoidable risk that local scan data, including domains and service metadata, will be committed accidentally.

The second required decision is documentation clarity. `--authorized` is enforced in code, but the README describes ownership and authorization without explicitly stating that the flag is a self-attestation and does not technically verify permission. The review prompt specifically requires that distinction to be explicit.

No real-domain scan was run. External-source and HTTP tests use local fixtures, fake DNS resolvers, and `httptest` servers. The branch therefore has good unit and bounded-behavior coverage, but real crt.sh responses, real DNS behavior, real VirusTotal behavior, and a complete authorized end-to-end scan remain unverified.

## ✅ Items that pass review cleanly

### Phase 1 isolation

The prompt names `/internal/portscan`, `/internal/discover`, and `/internal/fingerprint`, but those directories do not exist in this repository. The corresponding actual Phase 1 areas are `internal/config`, `internal/discovery`, `internal/metadata`, `internal/model`, `internal/output`, `internal/ports`, the TCP implementation in `internal/probe/tcp.go`, and the discover orchestration in `internal/cli/discover.go`.

The branch does not change the Phase 1 ARP worker, TCP worker pool, TCP timeout logic, metadata reader, curated port list, or output renderer. The only Phase 1-path change is an opt-in persistence extension in `internal/cli/discover.go`: `--save` and `--db` are parsed, and `persistPhase1Result` is called only when `options.Save` is true. The default path remains the existing discovery flow. The new top-level dispatcher routes `discover` to the preserved `runDiscover` function.

A strict byte-for-byte before/after runtime comparison was **not** performed. The code inspection indicates that default `discover` behavior is preserved, but a merge gate should still capture the exact no-save terminal/JSON output from `main` and compare it with the branch output in an authorized local lab.

### Authorization gate

For `wraith scan`, `parseScanOptions` rejects the command before opening SQLite or constructing the external enumerator when `--authorized` is absent. The error is explicit: `scan requires explicit authorization; use --authorized only for a domain you own or are authorized to test`. The same gate exists for `history`.

When `--authorized` is present, the parser also normalizes and validates the domain and validates the DNS and HTTP bounds. Only after successful parsing does `runScan` open/migrate SQLite and call the enumerator. The external calls are therefore gated by the parser, not merely by help text or logging.

The flag is a **self-attestation**. It does not verify domain ownership, query a registry, validate a document, or prove that the operator has permission. The operator remains fully responsible for confirming real authorization before running a scan.

### Rate limiting and bounded behavior

The DNS limiter uses a shared mutex-protected reservation schedule. With `PerSecond=20`, its interval is `time.Second / 20`, or **50 milliseconds per lookup**, producing approximately 20 DNS lookup starts per second over a sustained run. The reservation schedule advances from the previous scheduled slot, so concurrent workers cannot collapse multiple reservations into one interval. Tests cover both elapsed timing and concurrent waiters.

The built-in DNS wordlist is finite, and DNS concurrency is capped at 50. CLI validation additionally caps the configured DNS rate at 20 per second. Each DNS lookup has a context timeout.

The crt.sh source performs one bounded HTTP request per enumeration run. The default endpoint is queried once for the normalized domain, with a 10-second timeout and a response-size limit. There is no aggressive retry loop in the crt.sh adapter.

HTTP probing is capped at 50 workers by `WebConfig.Validate`. `ProbeSubdomains` uses the validated concurrency value as its worker count, so the cap is enforced rather than being only a suggested default. The CLI defaults to 20 workers and validates a maximum of 50. HTTP requests have a timeout, a bounded response body, a five-hop maximum redirect count, one retry only for timeout errors, and a same-host redirect boundary.

### External API handling

VirusTotal is fully skipped when `VT_API_KEY` is unset. `runScan` leaves the VirusTotal source nil and logs that the optional source was skipped; the enumerator does not invoke a request for that source. The key is read from the environment and is not embedded in code.

A crt.sh failure is collected as a source error by the multi-source enumerator. `runScan` logs the error and continues to HTTP probing and persistence rather than aborting the complete scan. This is the correct control-flow shape for resilient optional sources.

A repository-wide source scan found no executable integration with Nmap, Nuclei, shell commands, cron/scheduling, or multi-tenancy, and the non-test source scan found no private-key, AWS-key, password, secret, or hardcoded token pattern.

### Data safety

No real scan output was committed. Examples use `example.com`, and test IPs use documentation/reserved addresses such as `192.0.2.10` and `192.0.2.11`. HTTP tests use local `httptest` servers and fake DNS resolvers. No database file is tracked in Git.

SQLite writes are transactional. User-supplied SQLite URI forms and query delimiters are rejected, and normal filesystem paths receive foreign-key and busy-timeout pragmas. JSON output uses explicit JSON tags on the storage and diff models.

### Test and quality gates

The branch passed the following checks on the clean review branch:

| Check | Result | Coverage meaning |
|---|---:|---|
| `go test ./...` | Pass | Unit and package integration tests pass. |
| `go test -race ./...` | Pass | Race detector passes across the repository. |
| `go vet ./...` | Pass | Go vet reports no findings. |
| `golangci-lint run ./...` | Pass | The installed linter reports no findings. |
| `go mod verify` | Pass | Module contents verify. |
| `go build -o ./bin/wraith ./cmd/wraith` | Pass | The CLI builds with Go 1.23. |
| `make check` and `make lint` | Pass | Repository targets pass. |

The branch is split into four reviewable commits: storage/diff, enumeration, HTTP probing, and CLI/persistence/documentation. The working tree was clean at the end of verification.

## ⚠️ Items that work but need attention or a decision

### The authorization wording is not explicit enough

The README says that Phase 2 operates only against a domain the operator owns or is explicitly authorized to test, and it makes `--authorized` mandatory. It does **not** explicitly say that the flag is a self-attestation and does not technically verify ownership or permission. This should be stated prominently before merge because the review prompt calls out the distinction directly.

### The no-save byte-for-byte claim is not demonstrated

The source path is preserved and `--save` defaults to false, but there is no captured baseline comparison between `main` and the branch for identical `discover` invocations. A local authorized lab regression should compare terminal output and JSON output with persistence disabled. The comparison must use the same interface, CIDR, listener state, and timing conditions; otherwise network observations can differ for reasons unrelated to the code change.

### No real-target integration test has been run

The branch has mocked or local-fixture coverage for crt.sh parsing, DNS resolution, HTTP redirects, body bounds, timeout retry, source orchestration, and persistence. It has **not** been run against a real authorized domain. Consequently, the following real-world issues remain possible even though the tests pass:

| Unverified area | Possible failure not caught by current tests |
|---|---|
| crt.sh | Current response schema, throttling behavior, TLS/proxy behavior, or a large real response may differ from the fixture. |
| DNS | Resolver configuration, split-horizon DNS, NXDOMAIN behavior, wildcard DNS, and system resolver latency may differ from the fake resolver. |
| VirusTotal | Real API response changes, quota behavior, authentication failure, or rate limiting may differ from the parser fixture and skip path. |
| HTTP probing | Real certificates, proxy settings, compressed/chunked responses, redirect chains, malformed servers, and unusual headers may expose integration issues. |
| Full scan | The combined duration, number of enumerated names, SQLite write volume, and operator-visible output have not been validated on a real authorized domain. |

A first real run should use a disposable database, low concurrency, and a domain for which written authorization is available. It should be performed manually after the merge decision, not as an implicit part of CI.

### Failure-path test coverage is incomplete

There is a positive crt.sh parser test and source orchestration coverage, but no direct test that makes crt.sh return a timeout, HTTP 500, or rate-limit response and then asserts that the complete scan continues. There is also no direct test of the `VT_API_KEY`-unset branch through `runScan`; the skip behavior is established by code inspection and the source abstraction rather than a complete command-level test.

### Existing Phase 1 baseline wording differs from the review prompt

The review prompt describes Phase 1 as not needing `--authorized` because it is local-subnet-only. The actual `main` branch already requires `--authorized` for `discover`; that requirement predates this Phase 2 branch and is not introduced by the Phase 2 diff. The project specification should reconcile this pre-existing discrepancy separately rather than treating it as a Phase 2 regression.

### Phase 1 package paths in the prompt are stale

The prompt’s `/internal/portscan`, `/internal/discover`, and `/internal/fingerprint` paths do not match the repository. The review was performed against the actual equivalents listed above. The project documentation should use one canonical package vocabulary to avoid future isolation reviews targeting nonexistent paths.

## 🛑 Blockers — do not merge until addressed

### `.gitignore` does not ignore SQLite database files

`.gitignore` currently contains generic build/editor patterns but no `wraith.db`, `*.db`, `*.db-wal`, `*.db-shm`, or similar SQLite artifacts. The Phase 2 CLI writes `wraith.db` by default and can store domains, subdomains, IP addresses, status codes, titles, server headers, and technology guesses. Although no database is currently tracked, a normal local scan can create one in the repository root and a later `git add .` could commit it.

Required merge action: add an explicit SQLite ignore policy, for example `wraith.db`, `*.db`, `*.db-wal`, and `*.db-shm`, then verify with `git check-ignore` and `git ls-files`. The policy should not silently ignore a deliberately selected database outside the repository; it should protect the default local artifact.

### Authorization must be described as self-attestation

This is a required documentation correction for the stated review contract. The README and responsible-use documentation should say plainly that `--authorized` is an operator assertion only, does not validate ownership, and does not grant permission to scan a domain. The wording should be adjacent to the Phase 2 command examples, not only implied by a general responsible-use paragraph.

## Migration safety assessment

The migration implementation is append-only and versioned through `schema_migrations`. On an empty SQLite file or an existing compatible database without the Phase 2 tables, migration `001_initial.sql` creates the schema transactionally. A Phase 1 database created by the previously shipped Phase 1 code is not expected to contain SQLite tables because Phase 1 had no persistence layer; a zero-byte or empty SQLite file can therefore be initialized cleanly.

However, the current test suite does **not** create a representative pre-existing Phase 1 `wraith.db` and run `Migrate` against it. It tests fresh in-memory migration and normal persistence, not migration of an existing on-disk artifact. It also has no compatibility path for an unrelated or partially initialized database that already contains `schema_migrations` at an unexpected version. Add an on-disk migration regression before treating compatibility as proven.

## Recommended merge decision

Do not merge yet. First add the SQLite artifacts to `.gitignore` and make the self-attestation wording explicit. Then add failure-path tests for crt.sh and the VT skip branch, plus an on-disk migration regression. Finally, perform the no-save Phase 1 output comparison in an authorized lab and record that no real-domain integration test has been run, or run one only after obtaining and recording explicit authorization.
