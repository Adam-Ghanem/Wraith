# T2 Central Scope Authority

## Authority chain

```text
T1 Authorization Record → exact scope version reference → T2 Scope Authority
→ R1/R10.5 policy and budget controls → R3 transport → approved execution owner
```

T2 owns canonical target-boundary decisions for newly persisted T2 scope versions. It checks the project, immutable scope version, canonical scope fingerprint, typed rules, and a valid T1 authorization record before allowing a target. The decision model is pure and deterministic.

## R3 and redirect safety

T2 never resolves DNS, sends HTTP, dials sockets, or executes a subprocess. R3 still independently parses each redirect hop and validates each resolved destination through its existing gateway. T2 can be called with a supplied redirect or resolved-IP target, so no prior allow decision is inherited by a new destination.

## Active-assessment adoption

The existing `assessmentAuthorizer` is the first compatible active adoption seam. If a T2 scope version is present, the seam requires a currently valid T1 authorization for that exact version, evaluates the selected target through T2, bounds execution expiry by the T1 record, and re-evaluates on lifecycle checks. This does not introduce an execution path or alter R3 transport ownership.

Legacy R1 scope records remain supported only where no T2 scope version has yet been created. That compatibility path is documented as a migration limitation and remains covered by the existing R1 tests; it does not create a new permissive target parser or transport bypass.
