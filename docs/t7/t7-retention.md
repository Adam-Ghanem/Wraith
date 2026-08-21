# T7 retention and purge boundary

Retention is policy-derived, project-scoped, deterministic, and read-only by default. A retention record binds a safe subject reference to a validated policy fingerprint, creation time, retention deadline, hold state, and canonical fingerprint. It evaluates to `active`, `held`, or `deletion_eligible`. A hold overrides expiry; a forged or cross-project record is rejected.

There is no scheduler, worker, automatic deletion, or read-side mutation. `wraith governance retention check` and `list` are read-only. `wraith governance retention purge` accepts only `--dry-run`, an explicit `--authorized` acknowledgement, and a valid existing T1 authorization record for the supplied project and scope. It creates no destructive executor and does not delete data. A future destructive purge requires an explicit, separately reviewed execution authority.

Existing rows introduced before T7 remain `legacy-governed`: they are not silently reclassified, granted new authority, or rewritten by migration 026. SQLite encryption at rest is still a deployment responsibility; T7 does not claim to provide it.
