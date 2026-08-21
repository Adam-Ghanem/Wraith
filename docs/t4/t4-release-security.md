# T4 Release Security Contract

T4 releases require the existing full Go and web quality gates plus `scripts/check-t4-trust-enforcement.sh`. The deterministic check confirms that the production engine requires a trust-context factory for non-dry runs, validates the context before dispatch, validates again at the adapter boundary, and keeps `internal/trustcontext` free of network and subprocess imports.

| Release condition | Required evidence |
|---|---|
| Derived authority is deterministic | Unit tests cover deterministic creation, forged fingerprints, insufficient assurance, project mismatch, task mismatch, and expiry. |
| Active paths fail closed | Engine and adapter regressions prove that missing context reaches no owner. |
| Compatibility is bounded | Legacy R1-only active paths are rejected before lifecycle dispatch; dry-run planning remains non-dispatching. |
| Existing controls remain | R1 acknowledgement, T1 lifecycle, T2 scope, T3 classification, R3 transport policy, and R10.5 budgets are retained. |
| CI detects regression | CI runs the deterministic T4 enforcement check after existing secret-marker checks. |
