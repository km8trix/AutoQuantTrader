# Wave 3 lane A: durable research jobs proposal

Historical lane design record. The integrated behavior and acceptance status are recorded in [the canonical plan](../IMPLEMENTATION_PLAN.md#18-current-wave-3-handoff), [the research runbook](../runbooks/personal-v1-research.md) and [the Wave 3 evidence index](../reviews/2026-09-09-wave3/README.md). Proposal-era permissions, names and open questions below are retained as design history.

Status: lane implementation authorized after root interface review. The implementation freeze below replaces the original proposed DTO/table shapes; the remaining proposal records the design rationale.

Baseline: W2 merged as `6ea218addaa38d1c36c69b6a7ffbe564d701f834` through PR #53. The current root assignment closes the checkout's historical W2-pending handoff and authorizes this W3 planning slice. No legacy contract, code, schema or migration is changed by this proposal.

## Implementation freeze

The authoritative shared definitions are in `packages/domain/research_job_contracts.py`, delegated to lane A. The request is `ResearchRunRequest(spec, conventions, inputs, owner_id, idempotency_key, trial_id, dataset_archive=None, settlement_calendar=None)`. Dataset/configuration/evaluation values are retained once in the complete W2 RunSpec. `inputs` refers to canonical encoded EngineInputs; the resolver returns EngineInputs and the worker checks spec equality and exact encoded input bytes.

`ObjectRef(object_sha256, byte_count, codec_version="personal-record/1")` admits only that typed codec and the existing W1 `personal-research-dataset-v1` archive codec. Its media type is the constant `application/json`. Inputs and calendars require the typed codec; archive references require the W1 codec; report publications require the typed codec. Objects are capped at 64 MiB, input/archive/calendar references at 32 MiB. Real current-vintage jobs require retained archive and calendar references. W3 process limits use one CPU core, exact MiB budgets, at least 128 MiB resident memory and 1–64 MiB output, retaining W2's other ceilings.

The accepted request has no transient acceptance time. The queued event records database acceptance time. Job identity is the versioned owner/idempotency-key digest; retry equality includes the entire request, including trial. Run identity is W2's `run-` plus 64 hex digits. Claim fields are job/attempt IDs, fence, lease revision, worker/process IDs, start and expiry. Attempt number equals the fence and is projected from immutable events. Job views expose owner/trial/status/times, retained attempt outcomes, cancellation intent, latest observed progress and optional publication; they expose no claim token or private path.

Root froze a 60-second half-open lease, ten-second independent heartbeat/control interval and at most three attempts. Only abandoned attempts recover automatically. Graceful shutdown records recoverable abandonment; owner cancellation is durable and terminal once stopped or recovered. The worker throttles same-stage supervisor callbacks to ten-second database heartbeats while checking local shutdown every callback. New attempts reset progress to unknown; unknown child counters remain null. Completion and incomplete reports are separate terminal publications, matching the actual ReportArtifact.report.status.

Exact orchestration entry:

```python
process_one_research_job(
    workflow, *, worker_id, worker_instance_id,
    resolver, runner, artifacts, codec, stop_requested=None,
) -> ResearchJobView | None
```

Resolver `resolve(request) -> EngineInputs`; runner `run(ResearchExecutionRequest(request, claim, inputs), *, control) -> ResearchExecutionOutcome`; control maps actual ResearchProgress to RunControl. The outcome contains a typed ReportArtifact only for completed/incomplete. Root's runner independently supervises the child and validates/rebuilds its report through the sole W2 implementation. The worker uses the current renewed claim to bind the durable publication.

Workflow methods are `launch`, `get`, `get_request`, bounded owner-scoped `jobs`, `request_cancel`, `claim_next`, `heartbeat`, `publish` and `finish`, with exact signatures in the shared protocol. `SqlResearchWorkflow(engine, *, codec)` additionally exposes `launch_in_transaction(connection, request)`: the connection must belong to that engine and have an active SQLite/PostgreSQL transaction; it never commits. Root's catalog uses this to register the experiment/trial inventory and all queued jobs atomically. `launch` delegates to that same path.

Codec injection is `encode_record(value) -> bytes` and generic `decode_record(payload, expected_type) -> T`; persistence does not import application code. The artifact port is `put(payload, *, codec_version="personal-record/1", max_bytes=MAX_OBJECT_BYTES) -> ObjectRef` and `read(reference, *, max_bytes=MAX_OBJECT_BYTES) -> bytes`. `LocalResearchArtifactStore` uses an owner-controlled 0700 root, exact 0600 regular files, no-follow bounded reads, content hashes, staged fsync, no-clobber linking and destination-directory fsync. Installed objects become visible to job/report queries only after the atomic SQL publication.

There are exactly five new table objects in `packages/persistence/research_schema_v2.py`, attached to existing metadata and exported as `RESEARCH_TABLES_V2`: objects (byte metadata only), jobs (immutable typed request), events (append-only), heads (reconstructed/CAS projection) and publications (unique job/attempt terminal). SQL run-ID columns are 68 characters. No provider/archive bytes are stored in SQL. Root owns migration 0039, revision verification, catalog/evaluation tables, API, codec, resolver, worker supervisor/composition, packaging and CI. Lane A does not edit those dependencies or the old fixture modules/tables.

Lane tests use the actual W2 engine/accounting/report with independent rational verification, imported generated Tiingo-format archives labelled as synthetic, explicit incomplete resource diagnostics, lifecycle/SQL tampering, transaction rollback, stale fences, cancellation and heartbeat bounds. Process evidence distinguishes sandbox inability to run the mandatory RSS probe from a reviewed execution where that probe works. No local test contacts a provider or reads credentials.

Lane verification: 72 selected new/legacy tests passed in 35.61 seconds, including the actual bounded worker and a killed claimant followed by fenced restart with one publication. Ruff, strict mypy for all ten lane Python files, and the current `check_personal_architecture.py` gate passed. The default desktop sandbox denies `/bin/ps`; the identical scrubbed local process checks passed through reviewed escalation. PostgreSQL migration/concurrency verification, root catalog/evaluation/API composition and the complete W3 product flow remain integration gates; this lane does not claim those checks have run.

## Existing seams and recommendation

`packages/domain/backtest_job.py` has useful append-only lifecycle validation, exact claim tokens, renewal, recovery and terminal-state invariants. Its input is explicitly `phase2-backtest-job-v1`: a fixture ID/version and old replay/report manifests are mandatory. `packages/persistence/backtest_workflow.py` reconstructs immutable payloads and uses transaction locking plus compare-and-swap heads, but verifies every job against `phase2_backtest_fixtures` and the old `BacktestReport`. `packages/application/backtest_worker.py` only accepts the golden catalog and synchronously invokes `run_golden_backtest`; it does not poll running cancellation or renew during execution. Its supplied wall clock is not database lease authority.

Keep those contracts, modules and tables readable and their tests intact. Implement small additive v2 job modules. Reuse the existing immutable SQL insertion primitives and transaction conventions where their contracts apply; do not stretch old fixture fields with placeholder identities or treat a W2 report as the old report type.

`apps/worker/personal_research.py` already builds explicit W2 inputs, checks build pins, supervises a scrubbed child, retains the per-user lock in that child, detects parent loss, enforces process limits and publishes an output without overwriting. Its child already uses the sole `run_causal_engine` with `PersonalAccounting`, `ReferenceStrategy` and `build_run_report`. Root should expose this process boundary as an injectable, reusable port. The durable orchestrator must not import `apps`, add a second scheduler, calculate metrics, or serialize arbitrary Python objects with pickle.

## Exact proposed file allowlist

Only this proposal is writable during planning. After root freezes interfaces, proposed lane A ownership is:

| New file | Responsibility |
| --- | --- |
| `packages/domain/research_job_v2.py` | Pure lifecycle transition functions over root-owned DTOs; request identity, event-chain, claim, cancel and terminal invariants |
| `packages/persistence/research_workflow_v2.py` | SQL catalog/request/event/head/attempt/publication implementation and sanitized durable queries |
| `packages/application/research_worker_v2.py` | Process-one orchestration with injected workflow, input resolver, bounded runner and artifact store |
| `packages/adapters/research_artifacts_v2.py` | Private content-addressed input/output storage, bounded regular-file reads, digest validation and no-clobber durable installation |
| `tests/unit/test_research_job_v2.py` | Pure transition and identity cases |
| `tests/unit/test_research_worker_v2.py` | Fake-port lease, cancel, crash and publication ordering cases |
| `tests/unit/test_research_artifacts_v2.py` | Filesystem boundary and crash-window cases |
| `tests/integration/test_research_workflow_v2.py` | SQLite transaction/reconstruction/race cases and PostgreSQL variants under the existing optional fixture |
| `tests/integration/test_research_worker_v2.py` | Actual small W2 engine/report path plus kill/restart publication evidence |

No existing file is proposed for lane A edits. Root owns the new shared `packages/domain/research_job_contracts.py`, shared codecs/read DTOs, schema definitions, migration IDs and files, API contract/routes/authentication, configuration, the worker entry/composition, W2 supervisor extraction, packaging/CI, and canonical documents. Root assigns any catalog/input resolver implementation explicitly; it is not implicitly lane A scope. Lane B owns evaluation/trial semantics. Lane C consumes generated contracts; it does not derive finance from job status.

## Immutable request and artifact identities

All DTOs below are frozen dataclasses with exact type validation and canonical versioned digests, using existing domain canonical utilities. Times are aware UTC. A semantic digest is distinct from a serialized object's byte digest. Digest-like identifiers are validated, and bounded text cannot contain paths, credentials or arbitrary exception messages.

Proposed shared DTOs and exact fields:

```python
ObjectRef(
    object_sha256: str,          # SHA-256 of exact stored bytes
    byte_count: int,
    media_type: Literal["application/json"],
    codec_version: str,
)

ResearchSelection(
    dataset_id: str,
    dataset_sha256: str,         # W2 content_digest((manifest, rows))
    dataset_archive: ObjectRef,  # includes factual import metadata independently
    settlement_calendar: ObjectRef,
    strategy_version: VersionPin,
    configuration_sha256: str,
    configuration: ReferenceConfiguration,
    evaluation_sha256: str,      # lane B's immutable fold/protocol record
    evaluation: EvaluationSpec,
)

ResearchRunRequest(
    selection: ResearchSelection,
    spec: RunSpec,              # the complete W2 spec; no mutable default lookup
    report_conventions: ReportConventions,
    requested_by: str,          # authenticated local principal ID, not account ID
    idempotency_key: str,
    requested_at: datetime,     # database accepted time
    trial_id: str,              # root/B binding; every accepted request is recorded
    contract_version: Literal["personal-research-job/2"],
)
```

`run_id` remains `spec.run_id`: semantic identity excludes job/attempt/generation timestamps. The request's computed `request_sha256` includes all immutable accepted selection/spec/convention/trial links. Its computed `job_id = digest((version, requested_by, idempotency_key))` identifies the launch command. A retry with the same principal/key and same submitted selection/spec/trial returns the original accepted request/time; a changed selection, trial or spec conflicts. A new idempotency key may request another attempt at the same semantic run, and must remain visible in the trial registry; do not globally deduplicate jobs by run ID.

The catalog stores accepted immutable archives and strategy/config records before launch. A private storage key is derived from `ObjectRef.object_sha256`, not supplied by a browser. Portable requests contain object IDs, byte lengths, semantic hashes, data class, limitations and permitted display labels, never absolute paths or provider payloads. Path resolution is adapter-private. Archive bytes and settlement-calendar bytes must be available after worker restart; a mutable original owner path is insufficient.

Admission validates the W1 archive with its existing decoder, preserves `ResearchDataset.dataset_id`, and separately checks W2's dataset digest, archive byte hash, calendar identity/coverage, explicit strategy/configuration pin and evaluation linkage. It creates or validates the full RunSpec through the accepted input builder. No launch runs economic code or fabricates a completed reference report. At execution, reconstruction must exactly match the accepted spec, event digest, initial-state digest and all pins; changed installed code or bytes fails visibly, rather than producing a new run under an old request. Final-session calendar-horizon and short-real-sample limitations remain explicit. Synthetic sources are separately labelled catalog objects; real selected archives need no fixture ID.

## Attempt, event and claim contract

```python
ResearchClaim(
    job_id: str, attempt_id: str, attempt_number: int,
    worker_id: str, worker_instance_id: str,
    fence: int, lease_revision: int, lease_expires_at: datetime,
)

ResearchProgress(
    stage: Literal["loading", "running", "validating", "publishing", "stopping"],
    processed_events: int | None,
    frontier_sequence: int | None,
    frontier_at: datetime | None,
)

ResearchAttempt(
    job_id: str, run_id: str, attempt_id: str, attempt_number: int,
    worker_id: str, worker_instance_id: str, fence: int,
    started_at: datetime, ended_at: datetime | None,
    outcome: Literal["running", "completed", "incomplete", "failed", "cancelled", "abandoned"],
    reason_code: str | None,
)

ResearchJobEvent(
    job_id: str, sequence: int, previous_event_sha256: str | None,
    kind: Literal["queued", "claimed", "renewed", "cancel_requested",
                  "attempt_abandoned", "completed", "incomplete", "failed", "cancelled"],
    occurred_at: datetime, actor_id: str,
    attempt_id: str | None, fence: int | None,
    evidence_sha256: str,
)
```

Fields have computed canonical hashes. Attempt records are projections of immutable events, not a mutable execution history. A claim references a process-instance ID, not a reusable PID. `fence` increases on each attempt, including reclaim by the same worker label. Renewal retains attempt/fence and rotates `lease_revision`; every write requires the current exact claim. Parent serializes heartbeats and completion so its own renewal cannot race with an obsolete token. Cancel requests are a distinct durable dimension and cannot be cleared by renewal.

The proposed v2 lease interval is half-open: authority requires `database_now < lease_expires_at`; equality permits recovery and blocks renewal/publication. This differs explicitly from the legacy equality rule, which stays unchanged. Database time is sampled inside the locked write transaction (PostgreSQL clock sampled after lock acquisition; SQLite current UTC inside `BEGIN IMMEDIATE`). API/client times and child simulated times never grant a lease. Reject regressed persisted transition times; do not clamp them forward. Process budgets use monotonic time independently.

Recommended defaults for root freeze: one active local research process, 60-second lease, heartbeat/control check at most every 10 seconds, at most three attempts, unchanged W2 per-attempt resource ceilings, and a finite durable automatic-recovery budget. A heartbeat does not reset the run's wall deadline or attempt cap. Progress remains an observation, not an economic checkpoint: W3 restarts from the identical immutable inputs and empty W2 product account. No partial account/strategy resume is claimed.

## Workflow and execution ports

These signatures place all lease authority and public state transitions in one workflow implementation. Public reads return sanitized projections; exact claim tokens stay worker-private.

```python
class ResearchWorkflowPort(Protocol):
    def launch(self, command: ResearchLaunchCommand) -> ResearchJobView: ...
    def get(self, job_id: str) -> ResearchJobView: ...
    def request_cancel(self, command: ResearchCancelCommand) -> ResearchJobView: ...
    def claim_next(self, *, worker_id: str, worker_instance_id: str) -> ClaimedResearchJob | None: ...
    def heartbeat(self, claim: ResearchClaim, *, progress: ResearchProgress) -> ClaimControl: ...
    def publish(self, claim: ResearchClaim, *, publication: ResearchPublication) -> ResearchJobView: ...
    def finish(self, claim: ResearchClaim, *, outcome: ResearchFailure) -> ResearchJobView: ...

class ResearchInputResolver(Protocol):
    def resolve(self, request: ResearchRunRequest) -> ResolvedResearchInput: ...

class ResearchRunnerPort(Protocol):
    def run(self, execution: ResearchExecutionRequest,
            *, control: Callable[[ResearchProgress], RunControl]) -> ResearchExecutionOutcome: ...

class ResearchArtifactStore(Protocol):
    def retain(self, staged: StagedResearchArtifact) -> ObjectRef: ...
    def verify(self, reference: ObjectRef) -> None: ...
```

`ResearchLaunchCommand` is the selected immutable input, principal, idempotency key and trial link before database acceptance time. `ResearchCancelCommand` contains job ID, principal and its own idempotency key. `ClaimedResearchJob` contains accepted request and current claim. `ClaimControl` contains renewed claim, database time and durable cancel flag. `RunControl` is `continue` or `stop` with a bounded reason (`cancel_requested`, `lease_lost`, `shutdown`, `resource_limit`); unavailable database authority requests stop. `ResolvedResearchInput` binds accepted spec and exact private object references or explicitly encoded EngineInputs. No arbitrary command line, module name or SQL credential is passed to the child.

`ResearchExecutionRequest` contains job ID, run ID, durable attempt ID, pinned spec/conventions, resolved input, and private output staging handle. `ResearchExecutionOutcome` contains W2 engine status, validated staged artifact reference or none, bounded reason, and measured process-exit/resource evidence. The supplied control callback runs in the supervisor while the child executes, not only between engine events. It renews the claim and observes cancellation independently of a stalled child. A root-owned bounded codec must validate exact `ReportArtifact`/RunReport/EngineResult types and hashes on return; a claimed hash in child JSON is insufficient. `ResearchPublication` contains job/run/attempt IDs, result semantic hash, report semantic hash, ReportArtifact semantic hash, stored byte ObjectRef, and completed/incomplete outcome. Never conflate the two artifact hashes.

The orchestrator function is `process_one_research_job(workflow, *, worker_id, worker_instance_id, resolver, runner, artifacts, stop_requested=None) -> ResearchJobView | None`. It has no database, engine, report or CLI imports beyond frozen port DTOs. The adapter/composition supplies actual implementations. Domain lifecycle code remains stdlib/domain-only.

## Cancellation, recovery and publication ordering

1. Launch atomically records the immutable job, queued event/head, and B's trial-attempt linkage. Duplicate command identity returns the accepted record. Accepted failed/cancelled/incomplete jobs remain queryable.
2. Claim locks the eligible head, increments the fence, opens a new attempt and returns database-bounded authority. A lost preceding attempt is closed as `abandoned` in the same transaction. An expired job with durable cancellation closes cancelled rather than rerunning. If recovery budget is exhausted, close failed with a bounded reason. No automatic retry of deterministic input/engine failure; only bounded abandoned-attempt recovery is automatic.
3. Worker holds the W2 per-user process guard before child start. The child inherits the guard and checks parent liveness. A lease recovery cannot create simultaneous local economic processes while an orphan still holds this guard. Acquire the guard before taking work, or promptly abandon/release a claim when the guard is unavailable; do not wait unbounded while consuming lease time. SQL fences protect publication even if local process exclusion fails.
4. Queued cancellation can close immediately without inventing an executed attempt. Running cancellation is persisted as `cancel_requested`, not falsely reported as stopped. Parent signals the child, applies W2 cleanup timeout/kill/reap, then closes the current attempt cancelled. If it dies first, recovery records abandonment and observes the existing cancellation before any new child. Worker shutdown is separately labelled; root chooses whether a gracefully interrupted attempt becomes recoverable abandonment or terminal cancellation.
5. Child writes only an attempt-private new file. Parent reaps it and validates sizes, source/spec/run/attempt identities, semantic report hashes, provenance and measured resource outcome. Actual engine `incomplete` may publish an explicitly incomplete diagnostic report; external cancel, resource kill or malformed output cannot masquerade as completed.
6. Artifact store installs validated bytes content-addressably without overwriting, fsyncs file and destination directory, and verifies any existing object byte-for-byte by hash/size. Installation happens before the database reference is committed. Only the database publication table makes an object visible through public job/report APIs; storage directory listing is not a publication mechanism.
7. One database transaction re-locks the job, checks the current unexpired claim and cancel flag, inserts/verifies the immutable publication, appends the one terminal event and advances the head. Enforce uniqueness by job and terminal attempt. If cancellation committed first, success publication fails; if publication committed first, later cancel returns the unchanged terminal result. No external I/O is inside retryable transactions.
8. Crash after artifact installation but before database commit leaves an unreachable object, never a completed job. Crash after commit before acknowledgement is resolved by reading the durable publication identity: identical retry returns it, contradictory bytes/outcome conflict. A stale attempt cannot attach its object to the job. Restart retains the original run ID and uses a new attempt ID, without duplicate terminal publication.

Do not promise exactly-once computation. W3 promises at most one visible terminal result for a job, with retained attempts and fenced publication; deterministic recomputation after an abandoned attempt is expected. Deleting unreachable objects is separate bounded maintenance, not required to make publication safe and not automatic in this lane.

## Additive table requirements for root

Logical names below are recommendations; root supplies the final schema symbols and migration ID. New writes never enter `phase2_*` fixture tables.

| Table | Required immutable identity / integrity |
| --- | --- |
| `research_objects_v2` | Byte hash primary key, size, media/codec; content-derived private storage key; local access policy separate from portable metadata |
| `research_datasets_v2` | Catalog ID, W1 dataset ID, W2 dataset digest, archive object FK, data class, exact manifest summary/hash; multiple factual import artifacts may reference one semantic dataset |
| `research_configurations_v2` | Strategy version pin + configuration hash/payload; immutable display/schema references; no arbitrary importable code path |
| `research_run_specs_v2` | Run ID primary key, full canonical W2 spec and validated readable payload, semantic/transport hashes, dataset/config/evaluation/convention links |
| `research_jobs_v2` | Job ID, unique principal/idempotency key, immutable accepted request/payload/hash/time, RunSpec and trial link |
| `research_job_events_v2` | Append-only `(job_id, sequence)` and event digest uniqueness, predecessor digest, typed event payload and database time |
| `research_job_heads_v2` | Mutable lockable projection of exact latest event; current status/attempt/fence/lease revision/expiry and cancel request; compare-and-swap predecessor |
| `research_attempts_v2` | Unique `(job_id, attempt_number)`, attempt ID/fence, current attempt projection backed by immutable event chain |
| `research_publications_v2` | Unique job ID and unique terminal attempt ID, run/result/report/artifact semantic hashes, byte-object FK, completed/incomplete status, publication event/time |

Cancellation command idempotency can be a unique command identity on immutable job events plus canonical payload; use a separate small command table only if root's API contract needs its own acknowledgement lifecycle. Object rows can be combined with existing immutable artifact infrastructure if its access/byte contract is exact. An attempt projection may be omitted if bounded event queries satisfy UI requirements. Do not store the entire 1-GiB report as a SQL text field by default; public report pagination/summary projections derive from validated artifacts and preserve explicit undefined metrics. Root decides bounded query indexes/page sizes and artifact access policy.

## Independent acceptance tests

| Input / fault | Required assertion |
| --- | --- |
| Same launch key twice; then changed config, dataset, evaluation or cost | Same accepted job/time for equal request; conflict for changed semantic input; a distinct key records a distinct trial/job even for the same run |
| Real-format repository archive plus explicit settlement calendar and reference config | Catalog → accepted request → actual W2 engine → actual derived report; hashes match direct W2 execution; retained exploratory/action/calendar limitations; no fixture identity or provider calls |
| Changed archive bytes, modified calendar, unknown object, wrong config pin, changed installed source | Reject before execution or publication; never silently update accepted RunSpec/run ID |
| Two claimants and same-worker-ID restart | Exactly one current claim; new process instance/fence distinguishes restart; old attempt cannot heartbeat, fail or publish |
| Database time at lease expiry and host wall-clock regression | Equality cannot renew/publish; database authority controls reclaim; monotonic process deadline is unchanged |
| Long fake child with periodic supervisor callback | Lease renews without an engine callback; progress contains only actually observed fields; heartbeat failure signals stop and prevents publication |
| Cancel while queued/running; cancel versus publish race | Queued has no fake executed attempt; running shows requested until child stops/reaps; transaction order yields exactly one terminal decision |
| Kill before child launch, mid-run, after staging, after object install, after terminal commit before acknowledgement | Restart records prior attempt and either safely reexecutes or returns the existing result; one terminal publication; no unfinished artifact exposed |
| Parent killed while child remains alive | Inherited per-user guard prevents second local child; orphan detects parent loss; stale claim cannot publish after recovery |
| Resource/event/output boundary and source mutation | Existing W2 limit semantics retained; bounded outcome and no false completed publication; no secret/environment/path/raw exception output |
| Report JSON with correct top-level hash but contradictory nested run/source/config identity | Strict decoder and recomputation reject; changing bytes cannot retain the accepted object hash |
| Stored job/event/head/publication tampering and transaction rollback | Reconstruct/compare detects inconsistency; partial terminal inserts and stale-head updates roll back together |
| Independent small flat/reference result | Existing Fraction verifier recomputes NAV/PnL/fees/TWR/benchmark from accepted financial facts; this lane adds no finance implementation |
| Legacy fixture lifecycle/reports and migration from merged W2 | Old rows remain readable and old tests pass; root's PostgreSQL concurrency/migration checks cover the actual new schema |

Use the exact W2 verification interpreter `/private/tmp/aqt-wave0-f152ahl7/venv/bin/python` with `env -i`, explicit worktree PYTHONPATH, bytecode disabled, plugin autoload disabled, no pytest cache and a unique temporary base. Initial planning requires only document/link/scope checks. No service, database, provider, credential or native-runtime activation is part of this proposal.

## Root decisions needed before implementation

1. Freeze shared DTO names/fields/codecs and approve the exact additive lane A allowlist. Confirm who implements catalog resolution and the safe typed RunSpec/report decoder.
2. Freeze schema symbols, migration and B trial-link atomicity. A trial is recorded for every accepted request and subsequent attempt/outcome; it is never inferred only from successful reports.
3. Expose W2's reusable bounded supervisor with durable attempt ID and independent heartbeat/cancel callback. Keep its one-engine composition and resource truthfulness; no shell-command construction from API input.
4. Freeze lease equality, TTL/heartbeat, attempt/recovery budget and graceful-shutdown treatment. Recommend 60s/10s/three attempts with half-open lease authority and restart-from-input semantics.
5. Approve filesystem object installation before atomic SQL publication as the local durability model, including directory fsync and access rules; choose whether incomplete W2 reports are published as a distinct terminal status (recommended).
6. Root/B resolve evaluation selection/reset support and real-archive horizon admission before the UI calls launch. No continuous account carry, PIT qualification, strategy success or trading authority follows from a completed research job.
