# R21 Security Review — Continuous Assessment Analytics

R21 is an offline, project-scoped derived-intelligence layer. It reads only persisted R18/R19/R20 state, performs no HTTP, DNS, socket, subprocess, scanner, scheduler, worker, cloud, credential, or telemetry operation, and does not mutate its source records.

| Threat | Mitigation | Verification | Residual risk |
| --- | --- | --- | --- |
| Cross-project analytics leakage | Every query is parameterized and requires `project_id`; normalized records must match the requested project. | R21 storage isolation test requests `beta` after creating `alpha` history. | SQLite access remains trusted local access. |
| Forged R18/R19/R20 source | R18 snapshots are reconstructed, comparisons are recomputed, R19 evaluations use the canonical validator, and R20 states use the canonical validator. | Malformed source is excluded with explicit data-quality reason; invalid lineage fails closed. | Historical validity is limited to retained source records. |
| Forged or stale derived cache | Cached snapshot fingerprint is validated and the cache is returned only when a fresh canonical source reconstruction equals it. | Forged payload and source-change stale-cache tests. | A valid cache is still a summary of the selected bounded window. |
| Memory or output exhaustion | History, window, record count, source JSON, cached JSON, IDs, and export paths are capped. | Pure-model bounds and storage/CLI validation tests. | SQLite query cost depends on the bounded local database. |
| Secret-bearing identifiers | Source models and R21 model reject secret-like IDs; R21 retains fingerprints/counters, not raw evidence or URLs. | Boundary validation and staged secret scan. | Upstream persisted source quality remains an owner responsibility. |
| Report/terminal injection | R21 uses the existing R16 model and renderer; its projection contains bounded enum-like values, counts, fingerprints, and limitations only. | Existing report escaping tests plus R21 report-model validation. | Existing renderer limitations remain tracked by R16. |

R21 reports `insufficient`, `partial`, or `contradictory` data quality rather than treating missing, malformed, or unavailable history as healthy. The Assessment Health Index is not a vulnerability score and does not replace R11.5 risk.
