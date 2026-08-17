# Wraith Phase 2 Implementation

## Purpose and authorization boundary

Phase 2 adds local persistence, change detection, passive and active subdomain enumeration, and bounded HTTP/HTTPS metadata collection. These capabilities are intended only for domains that the operator owns or is explicitly authorized to test. The CLI requires `--authorized` for `scan` and `history`; the flag is an acknowledgement, not a substitute for written permission.

Phase 2 does not alter the Phase 1 local IPv4 discovery boundary or its core ARP/TCP worker pools. It does not add content discovery, JavaScript analysis, subdomain port scanning, Nmap, Nuclei, a REST API, a dashboard, export formats, scheduling, or multi-tenancy.

## Migration strategy

SQLite migrations are embedded from `internal/storage/migrations/` and applied in ascending filename order. The `schema_migrations` table records each numeric version and migration name. `DB.Migrate` runs the migration table creation, pending migration statements, and migration-record inserts inside one transaction. A future phase can add `002_*.sql` without rewriting or replacing `001_initial.sql`; Phase 2 data remains available because migrations are append-only and versioned.

SQLite is opened with foreign-key enforcement and a five-second `busy_timeout` pragma. The connection pool is bounded, and every write operation uses an explicit transaction. A failed insert or migration rolls back its transaction and returns an error to the caller.

## Diff engine design

The diff engine uses separate typed snapshot structs with the same three-state result vocabulary: `NEW`, `REMOVED`, and `CHANGED`. `DiffDevices` indexes snapshots by IP and emits `CHANGED` only when the serialized open-port set differs, as required by the Phase 2 contract. `DiffSubdomains` indexes by fully qualified subdomain and emits `CHANGED` when status code, technology guess, or resolved IP differs.

The functions are pure: they accept in-memory previous/current slices, do not access SQLite, and return deterministic, sorted change slices. SQLite is responsible only for loading the two latest snapshots. This keeps the change semantics easy to unit-test and reusable for the Phase 1 device table and Phase 2 subdomain table.

## New and modified files

| Change | Files | Responsibility |
|---|---|---|
| New | `internal/storage/db.go`, `models.go`, `diff.go`, `migrations/001_initial.sql` | SQLite lifecycle, versioned migrations, transactional writes, readers, and pure diffs. |
| New | `internal/enum/dns.go`, `sources.go`, `wordlist.go` | Domain validation, crt.sh, optional VirusTotal, bounded DNS brute force, deduplication, and rate limiting. |
| New | `internal/probe/web.go` | Bounded HTTP/HTTPS probing, redirects, title/header extraction, retry policy, and technology guesses. |
| New | `internal/cli/phase2.go`, `phase2_run.go` | `scan` and `history` parsing, orchestration, persistence, and output. |
| Modified | `internal/cli/discover.go` | Adds opt-in `--save --db` persistence while retaining the existing discovery path. |
| Modified | `cmd/wraith/main.go` | No command-specific change is required; it continues to dispatch through the shared CLI entry point. |
| Modified | `README.md` | Phase 2 usage, database inspection/reset guidance, and authorization notice. |

## Bounded behavior

The built-in DNS wordlist is finite. DNS brute force is capped at 50 workers and 20 resolutions per second, with a per-resolution timeout. Passive HTTP sources have explicit request timeouts and response-size limits. VirusTotal is used only when `VT_API_KEY` is set; otherwise it is skipped with a clear log message. A source error is recorded and logged while the other sources continue.

HTTP probing uses at most 50 workers, a five-second default request timeout, one retry only for timeout errors, a five-hop redirect ceiling, and a bounded response body. It probes HTTPS and HTTP for each deduplicated subdomain but stores one best available subdomain record. A successful result is not overwritten by a later failed scheme.

Technology output is always labeled as `tech_guess`. Header and meta-generator patterns are heuristic evidence and are not vulnerability findings or confirmed platform identity.

## Authorized test procedure

Do not run a real Phase 2 scan until you have a domain you own or written authorization for. Build and test the code first:

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
export GOTOOLCHAIN=local
go test ./...
go test -race ./...
go vet ./...
go build -o ./bin/wraith ./cmd/wraith
```

Use a disposable database path and a low, bounded configuration for the first authorized run:

```bash
./bin/wraith scan \
  -d example.com \
  --authorized \
  --db ./phase2-test.db \
  --dns-concurrency 2 \
  --dns-rate 5 \
  --web-concurrency 2 \
  --web-timeout 5s \
  --verbose
```

Run the same command a second time, then inspect the diff:

```bash
./bin/wraith history -d example.com --authorized --db ./phase2-test.db
sqlite3 ./phase2-test.db '.tables'
sqlite3 ./phase2-test.db 'SELECT id,target,scan_type,completed_at FROM scans ORDER BY id DESC;'
```

If the database is only a disposable test artifact, remove exactly that file after stopping Wraith:

```bash
rm -- ./phase2-test.db
```

No public-target or bug-bounty target is authorized by this document. If no owned or explicitly authorized domain is available, limit testing to unit tests and local HTTP/DNS fakes.
