# R22 Decision Model

## Scope

R22 interprets verified continuous-assessment intelligence. It does not alter the source intelligence or perform a recommended action. One decision snapshot represents one bounded, project-local, freshly validated source state at an explicit UTC `as_of` time.

## Candidate state

| State | Meaning | Execution implication |
| --- | --- | --- |
| `allowed` | The candidate has sufficient validated source quality for a recommendation. | None; recommendation remains metadata only. |
| `degraded` | The candidate is visible but its confidence is reduced by explicit source limitations. | None. |
| `blocked` | A constraint prevents R22 from offering an actionable recommendation. | None; R22 must not circumvent the constraint. |
| `unknown` | The required validated conclusion cannot be derived. | None; absence is not safety. |

## Priority and confidence

R22 priority values are `P0` through `P4`. The pure evaluator assigns a bounded score from fixed factors, maps it to a priority, and then applies constraints. It never consumes or creates an R11.5 risk score. Factor explanations use only fixed templates selected from validated factor types.

| Priority | Decision meaning |
| --- | --- |
| `P0` | Immediate review is recommended because verified high-impact regression/evidence conditions meet fixed criteria. |
| `P1` | High-priority review is recommended because verified regression, policy, governance, or health signals meet fixed criteria. |
| `P2` | Medium-priority review is recommended from verified but lower-impact conditions. |
| `P3` | Low-priority review is recommended from verified informational conditions. |
| `P4` | Informational observation only. |

`high`, `medium`, `low`, and `unknown` confidence describe the decision's source quality, not exploitability, remediation, or safety. Contradictory/invalid data blocks a candidate. Stale, partial, or insufficient data reduces confidence or makes the candidate `unknown` according to fixed rules.

## Recommended actions

Supported recommendation labels are `investigate_regression`, `verify_evidence`, `review_governance`, `review_policy`, `increase_coverage`, `refresh_baseline`, and `resolve_data_quality`. They are not commands and cannot call R13/R14/R15, a transport, an adapter, or a worker.

## Fingerprint and lineage

The decision snapshot fingerprint covers schema/decision version, project, source fingerprints, explicit evaluation time/window, data quality, limitations, sorted candidates, factors, constraints, recommendations, and lineage. Every candidate references only safe fingerprints for its R18 comparison, R19 evaluation/policy, R20 governance state, and R21 analytics snapshot. Recomputing against changed source state produces a distinct snapshot; cache lookup requires both canonical snapshot validity and equality with fresh reconstruction.
