# R20 Governance Contract — Continuous Assessment Operations

## Purpose and decision boundary

R20 records deterministic local **operator treatment** of an existing R19 recommendation. A governance decision is neither remediation nor validation. It does not execute a task, perform a scan, change a finding, alter a risk score, refresh evidence, expand authorization, or establish that a system is secure.

> `accepted`, `deferred`, `rejected`, and `completed` are recorded operational states. They are not evidence that remediation occurred, that a recommendation was revalidated, or that authorization remains current.

R20 is project-scoped and offline. It consumes canonical persisted R18 snapshots/comparisons and R19 policy, baseline, evaluation, and recommendation records. It emits only local SQLite state, immutable audit events, machine-readable status, and R16 report projections.

## Model and ownership

| Object | Owner | R20 rule |
| --- | --- | --- |
| R18 snapshot and comparison | R18 | R20 validates and references them through a persisted R19 evaluation; it never recalculates, changes, or replaces them. |
| R19 policy, baseline, evaluation, and recommendation | R19 | R20 validates the canonical persisted evaluation/action before governance; it never changes policy or recommendation content. |
| Recommendation governance state | R20 | A project/action/evaluation-scoped current operational state. Its absence means `recommended`. |
| Operational decision and governance event | R20 | Immutable local audit lineage for one successful transition. It stores bounded, secret-screened actor and reason metadata only. |
| Governance status | R20 | A derived, fingerprinted view over recorded R19/R20 state. It never infers remediation, authorization, evidence freshness, or coverage. |

## Lifecycle

The lifecycle fails closed. Every transition requires the selected project, canonical R19 action identity, exact current expected state, explicit command, non-empty bounded reason, bounded actor, and an injected UTC time.

| Current state | Permitted next state |
| --- | --- |
| `recommended` | `acknowledged`, `accepted`, `deferred`, `rejected`, `expired` |
| `acknowledged` | `accepted`, `deferred`, `rejected`, `expired` |
| `accepted` | `completed`, `expired` |
| `deferred` | `completed`, `expired` |
| `rejected`, `completed`, `expired` | No transition |

The state and the corresponding decision/event append occur in one SQLite transaction. The transition compares the stored fingerprint with the caller’s expected predecessor. A competing or stale transition returns a conflict and appends no second event. Replaying the exact same deterministic event is idempotent. If decision/event persistence fails, the state write rolls back.

## Command contract

```text
wraith govern status --project PROJECT [--max-age DURATION] [--as-of RFC3339]
wraith govern recommendations --project PROJECT [--state STATE]
wraith govern acknowledge|accept|defer|reject|complete \
  --project PROJECT --recommendation ACTION \
  --expected-state STATE --reason TEXT [--actor ACTOR] [--as-of RFC3339]
wraith govern history --project PROJECT [--recommendation ACTION]
wraith govern check --project PROJECT [--strict] [--max-age DURATION] [--as-of RFC3339]
```

All commands use project-filtered local SQLite reads/writes. `status`, `recommendations`, and `history` are read-only. Transition commands only write R20 governance state, decision, and event records; they cannot delegate to an execution owner.

`check` returns exit code `0` for healthy non-strict posture, `1` for governance failure, `2` for invalid input, and `3` for explicitly classified internal failure. A strict check fails for `failed`, `stale`, and `unknown` posture and for unresolved high-priority R19 recommendations. A project without a persisted R19 evaluation has explicit `unknown` status with `assessment_evaluation_unavailable`; strict mode fails closed.

## Status semantics and limitations

| Status | Recorded meaning | It does not mean |
| --- | --- | --- |
| `healthy` | No policy failure/regression/staleness/unresolved action was represented in the selected recorded inputs. | Complete coverage, current authorization, absence of vulnerabilities, or completed remediation. |
| `degraded` | One or more recorded recommendations remain unresolved. | An active incident or exploitable weakness. |
| `failed` | The selected persisted R19 policy failed or its R18 comparison recorded a regression. | Root cause, exploitability, or required remediation. |
| `stale` | A configured maximum evaluation age was exceeded. | That R18/R19 data changed or that a new assessment has run. |
| `unknown` | Required governance/assessment information is unavailable. | A pass, a clean baseline, or safe evidence. |

R20 currently records no authenticated operator identity, approval workflow, evidence-of-remediation model, event retention policy, remote audit replication, scheduler, worker, or remediation executor. Those capabilities require a separate ownership, authorization, lifecycle, cancellation, retention, and threat-model review.

## Reporting

R16 remains the only renderer. Executive output contains aggregate governance status, unresolved-action count, and stale-reason count. Technical output includes safe policy/baseline/evaluation/comparison fingerprints, deterministic stale reasons/limitations, and decision/event lineage. HTML remains escaped and output files retain existing local permissions. Reports state recorded status and limitations only.

## Explicit non-goals

R20 adds no HTTP client, DNS resolver, socket, process execution, scheduler, worker, remote service, credential persistence, action executor, campaign/task creator, finding/risk/evidence mutation, R17 snapshot mutation, R18 comparison mutation, R19 policy/evaluation/action mutation, scope expansion, or authorization bypass.
