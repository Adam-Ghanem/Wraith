# R14 — Campaign Orchestration and Bounded Repeatable Assessment Cycles

R14 adds a **local, project-scoped orchestration layer** around the existing R13 plan, R13.1 owner registry, R13.2 execution engine, R10.5 shared controls and lifecycle storage, and R11.6 immutable surface snapshots. It does not add a scanner, transport client, resolver, socket, worker, queue, cloud scheduler, credential store, evidence store, finding engine, or risk formula.

> “Continuous” in R14 means an operator can create an explicit, finite later cycle from local durable state. It does not mean a background service runs indefinitely or that newly discovered targets become authorized automatically.

## State and ownership

| State concern | R14 behavior | Owner retained |
| --- | --- | --- |
| Campaign | Explicit `draft → planned → ready → running → paused|completed|failed|cancelled|expired` transitions; terminal campaigns do not become runnable. | `internal/campaign` |
| Campaign task | Explicit pending/ready/running/terminal task transitions; completed task IDs are never scheduled again. | `internal/campaign` |
| Scope and target | Campaign creation and explicit run load the active R1 scope/version and use the existing evaluator. R13.2 repeats authorization before execution and dispatch. | R1 and R13.2 |
| Plan and dispatch | Campaigns retain a validated secret-screened R13 plan. A cycle filters only checkpoint-approved work and delegates exclusively to R13.2. | R13, R13.1, R13.2 |
| Transport budget/rate/concurrency | One R10.5 `RunContext` is constructed per cycle. Campaign fields do not create an independent egress authority. | R10.5 and R3 |
| Surface | Campaign creation captures and persists an R11.6 snapshot reference: project, ID, fingerprint, and source version. | R11.6 |
| Execution lifecycle | One R10.5 run uses the unique cycle ID; R13.2 persists summary phase/events through that existing run. | R10.5 and R13.2 |
| Campaign lifecycle | Project-scoped campaign/cycle/task/checkpoint/event rows hold references, bounded statuses, and deterministic checkpoint state. | R14 |

## Checkpoints and later cycles

Each checkpoint includes a deterministic SHA-256 fingerprint over campaign ID, cycle ID, project ID, scope version, surface snapshot ID, sequence, and sorted completed/pending/blocked/failed task IDs. It excludes raw bodies, payloads, cookies, headers, tokens, credentials, and evidence content. Verification fails closed when a fingerprint, task list, or reference is altered.

A later cycle accepts an explicit completed set and, when supplied, an explicit eligible set. It removes only dependencies known to be durably completed and rejects an absent dependency rather than silently treating it as complete. This preserves dependency correctness without replaying completed tasks or turning failed/blocked tasks into automatic retries.

## CLI lifecycle

```text
wraith pentest campaign create TARGET \
  --project PROJECT --authorized --scope-version VERSION \
  --profile safe|standard|deep [--db PATH] [--json]

wraith pentest campaign status CAMPAIGN_ID \
  --project PROJECT [--db PATH] [--json]

wraith pentest campaign run CAMPAIGN_ID \
  --project PROJECT --authorized [--dry-run] [--db PATH] [--json]
```

`create` is local: it validates R1 authorization, constructs a deterministic R13 plan, verifies R13.1 ownership bindings, records an R11.6 snapshot reference, and creates campaign events. It does not execute an adapter.

`run --dry-run` validates the persisted plan, active scope, R13.1 registry, R10.5 controls, and R13.2 execution contract without creating a campaign cycle, R10.5 lifecycle run, checkpoint, or adapter dispatch. It therefore performs no campaign-owned egress.

An explicit non-dry run creates a project-scoped cycle and an R10.5 lifecycle run, then delegates to R13.2. The repository’s built-in owner bindings remain intentionally unconfigured, so the current CLI demonstrates a durable **partial, fail-closed** cycle with a checkpoint rather than attempting to recreate or bypass R4/R7/R11.x capability owners.

## Explicit non-goals and retained gap

R14 does not expose an asynchronous pause, cancel, resume, or recurring scheduler command because the repository has no safe persistent worker/owner-adapter configuration through which to stop or resume live owner work. A command that merely changed a database status would falsely imply it could interrupt or safely restart an owner-controlled request. The current checkpoint domain and eligible-task filter are the required safe substrate for a later explicit resume command once each real owner provides its lifecycle/cancellation contract and localhost E2E proof.

Likewise, a changed R11.6 graph does not expand authorization. A new asset, endpoint, parameter, or visibility gap remains data until a fresh R1 evaluation authorizes an explicit campaign creation or later-cycle plan. R14 does not create or modify findings; validated findings, correlation, risk, and evidence remain owned by R11.4, R9, R11.5, and R2.
