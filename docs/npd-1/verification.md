# NPD-1 Verification and Regression

NPD evidence remains an ordinary R2 observation and can be correlated by the existing evidence verification machinery using its project/task/authorization lineage.

For regression, `internal/npd/regression.go` projects each canonical port/state into the existing R18 snapshot `EndpointIDs` representation. This deliberately reuses R18 rather than creating a second comparison engine. A state transition therefore appears as a deterministic removal/addition of the corresponding port-state surface identity.

A missing observation is not converted to `closed`; incomplete or cancelled scans remain incomplete in the assessment lifecycle.
