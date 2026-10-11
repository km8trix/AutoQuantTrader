# Decisions

This is the concise current decision register. It indexes rather than replaces accepted [ADRs](adr/README.md), the frozen [personal-v1 contracts](contracts/personal-v1/README.md) and [architecture](ARCHITECTURE.md). Historical ADRs retain the facts and contract semantics they recorded. [ADR 0127](adr/0127-personal-use-architecture-consolidation.md) and the subsequent [account amendment](contracts/personal-v1/account-eligibility-amendment.md) govern target changes; implementation remains subject to its acceptance gates. A rationale is stated only where the source records it.

| Decision | Established rationale | Consequences and constraints | Record / implementation |
|---|---|---|---|
| Personal, single-owner/account/strategy, daily-first ETF scope | ADR 0127 explicitly adopts a useful personal tool and simplifies the prior program. | DIA/IWM/QQQ/SPY initial scope; cash-funded, long-only, whole-share regular-session orders. No SaaS, multi-account routing or automatic expansion of instrument/order scope. | [Architecture](ARCHITECTURE.md), [scope/defaults](contracts/personal-v1/scope-defaults.md), [ADR 0127](adr/0127-personal-use-architecture-consolidation.md). |
| One causal engine behind adapter ports | Separate research/trading engines could diverge in clock, ordering, fill, accounting and risk semantics. | Preserve deterministic availability-time behavior and canonical reducers; replacing the engine requires differential evidence and a superseding decision. Golden fixtures remain oracles, not the default product engine. | [ADR 0006](adr/0006-engine-boundary-and-build-strategy.md); `packages/application/causal_engine.py`, `apps/worker/main.py`. |
| Preserve data knowledge and evidence classes explicitly | Historical publication/availability evidence can be missing; stronger claims cannot be inferred from present-day samples. | Imported/current-vintage exploratory data may support labeled research; receipt-time capture, PIT evidence, synthetic simulation and actual provider results remain distinct. No historical/backtest result implies future returns. | [ADR 0127](adr/0127-personal-use-architecture-consolidation.md); `research_dataset.py`, `personal_forward_capture.py`, personal-v1 core contracts. |
| Append-only balanced ledger, Decimal arithmetic and derived FIFO/account projections | Mutable position rows cannot explain late fills, cash movements, fees, actions or corrections. | Correct by traceable new facts; never change historical entries or treat a mutable projection as independent truth. Deposits/withdrawals are not investment profit. | [ADR 0003](adr/0003-ledger-accounting-and-mandatory-risk.md); domain `ledger_reducer.py`, `account_projection.py`, `settlement_ledger.py`, `corporate_action_ledger.py`; `backtest/personal_accounting.py`. |
| Whole-batch risk/reservations and account-serialized publication | Sequential order checks can reserve the same capacity twice. | Decision, reservations and outbound work bind to current account/control/policy/lease state. Pending/UNKNOWN/cancel-pending commitments retain capacity; new daily policy cannot reinterpret the old paper risk envelope. | [ADR 0003](adr/0003-ledger-accounting-and-mandatory-risk.md), [ADR 0068](adr/0068-owner-approved-moderate-paper-risk-policy.md), [ADR 0127](adr/0127-personal-use-architecture-consolidation.md); `daily_risk.py`, `daily_runtime_risk.py`, SQL continuous account composition. |
| One fenced account coordinator; no automatic live failover/re-arm | SQL and broker requests cannot commit atomically, and the broker does not enforce local fencing. | Persist attempts before I/O, revalidate ownership/controls, preserve uncertainty and require reconciled owner re-arm. Restart/CI/health success cannot authorize new exposure. | [ADR 0004](adr/0004-broker-submission-and-account-ownership.md), [ADR 0096](adr/0096-etrade-live-broker-and-sandbox-qualification.md); account-coordinator, daily-attempt and runtime-owner repositories. |
| E*TRADE selected as future live broker; Alpaca evidence preserved as historical | Provider endpoint, account, lifecycle and recovery assumptions differ; E*TRADE sandbox is protocol-only. | Separate environment/secret/account scopes. Preview is not Place authority. E*TRADE's client ID is not an automatic ambiguous-order lookup key; no blind resubmission. Current bounded GET/OAuth code does not close order-execution qualification. | [ADR 0096](adr/0096-etrade-live-broker-and-sandbox-qualification.md), E*TRADE modules under `packages/adapters/broker/`. |
| CASH or MARGIN account privileges may be eligible while strategy remains cash-funded | The owner explicitly amended account selection after observed production account semantics. | No borrowing, leverage or larger risk permission follows from the amendment; liabilities, cash/restrictions, identity and reconciliation still need qualification. | [Account eligibility amendment](contracts/personal-v1/account-eligibility-amendment.md). |
| Stateful local simulated venue independently persisted from coordinator | Accepted design requires non-live stateful lifecycle testing; E*TRADE stored sandbox samples cannot supply economic fill evidence. | Compare expected coordinator state with independently modeled observations. Simulation/soak evidence cannot establish real execution quality or provider reconciliation. | [Architecture](ARCHITECTURE.md), personal-v1 account/runtime contract; `application/stateful_venue.py`, `persistence/stateful_venue.py`, continuous reconciliation/delivery modules. |
| PostgreSQL operational persistence; local SQLite supported for research/fixtures | Architecture retains existing real transaction/migration/ownership investment. A separate historical rationale for every SQLite use is not recorded. | Preserve additive migrations and PostgreSQL concurrency tests. SQLite local success and a `durable` API label do not establish deployment durability. Migration head is currently `0040_personal_continuous`. | [Architecture](ARCHITECTURE.md); `persistence/database.py`, `sqlite_config.py`, `apps/worker/research_jobs.py`, continuous factory. |
| Local private authenticated browser/API surface | A local personal workflow should not first require public ingress or a remote identity provider. | Loopback-bound configuration, signed HttpOnly session, CSRF and idempotency remain mandatory for relevant mutations. API startup rejects paper/live. Remote access is a separate reviewed design. | [ADR 0127](adr/0127-personal-use-architecture-consolidation.md), [ADR 0073](adr/0073-authenticated-local-operations-api.md); `apps/api/config.py`, `backtest_views.py`, `personal_research_views.py`. |
| Standard process/time profile; preserve legacy native lifecycle outside active prerequisites | ADR 0127 explicitly reduces personal-v1 operational complexity while retaining time/ownership/recovery safety. | Ordinary wheel native build is opt-in. Retain pure time checks, source/effect boundaries and historical native artifacts/migrations; do not bypass sealed legacy guards or activate native resources to make normal tests pass. | [ADR 0127](adr/0127-personal-use-architecture-consolidation.md), [native dependency map](contracts/personal-v1/native-dependency-map.md); `pyproject.toml`, personal architecture checker and clock/runtime modules. |
| Existing continuous worker performs only HALTED restore/integrity | Source explicitly restricts operation/profile and requires existing private independent stores; detailed prior approval is tracked in the wave evidence. | No initializer, re-arm, provider polling loop or new first-send authority may be inferred from the worker's existence. Maintain original lease/resource limits while repairing startup cost. | `apps/trader/continuous_simulation_factory.py`; [Wave 4 integration evidence](reviews/2026-09-24-wave4-integration/README.md). |

For a material new choice, record the context, chosen behavior, known rationale, consequences, affected contracts and validation. Create a superseding ADR when changing an accepted architectural contract; never edit historical evidence into a new approval.

## 2026-09-26 — durable autonomous-development memory

**Decision:** keep AGENTS operational; use SPEC for product facts, PLAN for the
small executable queue and STATUS for the latest handoff. Retain the established
IMPLEMENTATION_PLAN wave requirements, frozen contracts, ADRs and dated evidence.

**Rationale:** the audit found a 27 KB chronological agent handoff and README
claims predating the current personal research path. Fresh tasks need one concise
entry point without losing historical acceptance boundaries. This follows the
owner's explicit autonomous-development request.

**Consequences/constraints:** archive the previous handoff byte-for-byte; update
STATUS after meaningful progress; never copy old authorization or a local pass
into current operational acceptance. Work in an isolated branch to preserve the
original integration checkout and its preexisting architecture edit. This changes
no trading authority, financial policy, schema or runtime behavior.

## 2026-09-26 — separate clock conversion ownership from qualification

**Decision:** add optional original reading-to-measurement evidence to the existing
Chrony bridge. Preserve its legacy call and leave `StandardClock` health rules,
runtime profiles and genuine-capture denial unchanged.

**Rationale:** the bridge's source ID identifies authority configuration rather than
an individual reading. A later capture-clock owner needs the actual conversion
association; a matching hash or freely reconstructed healthy record cannot supply it.
The repository already uses process-local original-object registries for this purpose.

**Consequences/constraints:** verification checks the original weakly referenced owner,
records and source bindings without another source or clock read. Copies cannot
transfer ownership. This cooperating-process contract is not a hostile-code sandbox,
proof of freshness, health-history evidence, or host qualification. Preserve separate
acceptance for each boundary. The focused 92-case evidence and review corrections are
in the [dated assessment](reviews/2026-09-26-autonomy/README.md).

**Measured-health extension:** compose a fresh private `StandardClock` in an opt-in
owner, preserving the existing reducer rather than duplicating health mathematics.
Weak callback bindings and original state/observation checks retain history across
samples, including failures. This intentionally couples the owner to the reducer's
private state shape; changes need joint review and the independent behavior-comparison
tests. Historical verification does not read clocks, renew a measurement, qualify a
host or implement the capture clock port. Genuine integration waits for authentic
qualified-source inputs instead of introducing unused authority wrappers.

## 2026-09-26 — terminal child-exit probe publication ends its producer

**Decision:** stop the bounded probe producer after publishing its observation
sampled after the supervisor's original child-exit Event. Preserve the caller's
original post-exit, released-phase, receipt, cleanup and deadline checks.

**Rationale:** a controlled schedule reproduced an unnecessary second callback
starting after the required terminal observation and racing the 0.05-second final
join. The supervisor already defines a completed post-exit sample as its final
lifecycle input; continuing callbacks beyond it serves no required observation.

**Consequences/constraints:** no earlier sample qualifies exit, no stale observation
can be refreshed while output drains, and Stop/error still precede receipt acceptance.
The original 0.5-second sample age, join/operation/lease/resource bounds and all
parent ownership checks remain. This fixes a reproduced race; the shared CI
`probe_stalled` reason does not establish which internal stall branch actually fired.
[Evidence](reviews/2026-09-26-autonomy/probe-terminal-evidence.json) includes 95 unit
and 19 original worker/lifecycle integration passes; Linux acceptance remains open.

## 2026-09-26 — restore original semantic generator boundaries

**Decision:** withdraw the tuple/record scalar recursion shortcuts and restore
the original generator expressions in `semantic_value`. Keep the preexisting
exact-builtin dispatch; do not emulate generator exceptions with manual catches.

**Rationale:** independent comparisons reproduced direct `StopIteration` escape
where the original wraps it in `RuntimeError`, and different temporary-result
release while a failing traceback remains alive. Matching ordinary values and
hashes did not establish complete compatibility.

**Consequences/constraints:** preserve original field reads, exception chaining
and temporary lifetimes through Python's own generator behavior. Earlier timing
gains from the withdrawn shortcuts are historical evidence only. Performance
must be remeasured without changing acceptance limits. Do not reinstate the
shortcuts solely to meet a timing gate.

**Subsequent owner decision:** the owner explicitly approved the bounded offline
[factory-only verification design](reviews/2026-09-26-autonomy/factory-verification-seal-proposal.md).
This permits developing its separate restricted data-proof contract. Existing
handoff seals alone still do not prove fingerprint equivalence; detailed design,
tests and original gates are required. SQL/object/fence observations and all
current limits remain; no wider optimization or operational authority is granted.

## 2026-09-26 — bounded original factory attempt proof pilot

**Decision:** implement the explicitly approved A2.3 experiment at the private
factory daily-borrow boundary. Restrict admission to effect-free original data
and a finite implementation inventory; preserve the public source method and all
fresh observation/ownership checks. Use opaque operation/thread/borrow-bound
proofs, poison on rejected post-issuance use, and retire before handoff retention.

**Rationale:** the authentic retained-source diagnostic counted 72 eligible
fingerprints costing 3.169 s. Its data-only model suggested possible savings,
but omitted complete ownership/behavior costs. This justified implementation and
measurement, not adoption. Existing handoff seals do not establish fingerprint
equivalence; the owner separately approved this restricted contract.

**Consequences/constraints:** the CPython 3.12.13 native proxy/Mapping witness is
explicit and bounded; unsupported profiles use ordinary validation. The private
verifier, baseline state and ordinary interpreter remain trusted. Do not extend
this into arbitrary code attestation or a hostile-code sandbox. Original data,
implementation bindings and method identities are checked without accepting a
new baseline after issuance. All proof metadata counts against existing limits.
A useful complete-cost measurement, adverse genuine lifecycle tests, original
unprofiled retained/worker tests and exact-source Linux CI remain required.
Reject the pilot rather than enlarging limits or declaring partial tests complete.

**Validation checkpoint:** the `2a9fc2c` Linux matrix completed with 4,944 passed
and four failed financial tests; the pilot is not accepted. Its valid partial
profile establishes private-route entries, not completed restore or sufficient
savings. A2.4 therefore observes the two unchanged daily snapshot checks inside
original factory borrows, with no substitution or extra validation. The daily
identity predicate differs from the attempt projection; any proposal to replace
it needs a separate consequential decision after measured economics and shared
resource limits are assessed. See the [assessment](reviews/2026-09-26-autonomy/daily-identity-proof-decision-assessment.md)
and [current status](STATUS.md).

**Separate feasibility approval:** after reviewing the A2.4 result, the owner
explicitly approved the [daily identity feasibility experiment](reviews/2026-09-26-autonomy/daily-identity-feasibility-proposal.md)
only. Start with the shared-resource screen and reject a proposed layout before
building larger guards if it does not fit. This authorizes temporary offline
investigation, not production substitution or adoption.

**Feasibility disposition:** reject the stated daily per-node layout at its first
resource gate. Applying the established `retain` accounting to the authentic
visited-node/edge inventory already exceeds shared caps by 359 containers and
8,589 bindings, before other required costs. [Independent review](reviews/2026-09-26-autonomy/daily-identity-node-screen-independent-review.md).
Do not build its behavior/timing machinery or spend another fixture to seek a
smaller graph. This is a representation-specific rejection, not proof that every
possible daily proof is infeasible. Production validation remains unchanged.

## 2026-09-27 — bounded offline pre-lease study approval

**Decision:** the owner's “Go with your recommendation” approves the
[pre-lease study](reviews/2026-09-26-autonomy/prelease-restoration-decision-proposal.md)
for finite offline design and feasibility. Production adoption is not approved.

**Rationale:** the completed daily layout exceeded unchanged resource caps and
the source audit found no existing qualified handoff across lease acquisition.
The next question is whether provisional historical work can cross that boundary
through a narrowly owned transition while preserving every fresh check.

**Consequences/constraints:** resolve the original transaction predecessor/result,
race/ABA handling, fixed eligible pure work and joint resource/complete-cost model
before releasing a qualified-reuse prototype or candidate cost experiment. A
separately reviewed, non-substituting original-only observation may establish
the selected work's cost before that qualification. Preserve the original clocks,
limits, receipts, cleanup and all failed evidence. Reject infeasible designs;
this decision does not accept the attempt pilot or change production validation.

**Study disposition:** reject the narrowly selected CLOCK journal canonicality
reuse candidate. The reviewed original-only observation passed the unchanged
test and cleanup, but measured only 8.204 ms of repeated successful codec work
within 44.155 s execute (0.0186%). [Source-bound result](reviews/2026-09-26-autonomy/prelease-clock-original-result.json).
The additional acquisition-ownership, cold/warm behavior, fresh comparison and
retirement machinery is not justified by that small observed opportunity.
No candidate was benchmarked, so this is an engineering scope decision, not a
measured negative speedup or proof that every pre-lease design is infeasible.
The 42 observer mechanics cases include 29 author and 13 independent cases;
no production validation, risk control, resource cap or timer was changed.
Do not build the witness or expand the predicate from this result alone.


## 2026-09-27 — exact primitive contract admission

**Decision:** use the existing codec primitive-dispatch precedent in
`personal_contracts._check_type`: an already matching exact `str`, `int`, `bool`
or `NoneType` needs no generic typing introspection. Keep the original text bound;
all other annotations, values and errors retain the existing dispatch body.

**Rationale:** the source has redundant generic typing work for these exact native
annotations. A literal-original finite prototype preserves 52 result/error/hook
cases and improves selected synthetic primitive workloads. This supports a small
local change, not a prediction that retained restoration will meet its deadline.

**Consequences/constraints:** constructors still run and every field is checked.
No coercion, cache, proof extension, skip of fresh observations, or larger time/risk/
resource allowance follows. Supported custom annotations and metaclasses keep
original behavior; the skipped imported typing helpers are implementation details,
consistent with the existing codec path, not a new extension interface. Independent
constructor/oracle tests and applicable static/integration gates remain required.
A2's failed Linux acceptance stays open until its actual gates pass.

Ordered integration validation also exposed stdlib copy's lazy `__slotnames__`
cache leaking from earlier tests into the pinned reader/composer class inventory.
Restore that test-created metadata at the three copy sites, following the newer
proof tests' existing helper. Keep real copied objects and all denial assertions;
do not refresh the production baseline or exempt the cache from its guard.
[Reproduction and corrected ordered checks](reviews/2026-09-26-autonomy/contract-copy-isolation-correction.json).

## 2026-09-27 — bounded native Linux child observation

**Decision:** replace Linux's per-observation `ps` subprocess with one bounded
procfs status acquisition. Retain the original ps helper on other platforms,
the existing current-RSS/state result and all original supervisor decisions.

**Rationale:** the preserved `071dd5c` worker failure identifies a handled
`TimeoutExpired` in the 0.1-second ps observation. Reviewed kernel/procps source
supports using status `State` and `VmRSS`; the repository already uses bounded
procfs reads. This removes process launch/communication/reaping from each Linux
observation without claiming a measured speedup or identifying scheduler causes.
[Source and design review](reviews/2026-09-26-autonomy/linux-child-observation-design-screen.md).

**Consequences/constraints:** read at most 16 KiB plus one rejection byte through
a no-follow regular descriptor; require exact PID/Tgid, accepted state codes,
strict keys/RSS and a late mandatory completeness marker. A wholly absent memory
section yields zero RSS, including a non-Z exit transition; only Z proves exit.
Preserve primary errors, descriptor closure and the original deadline through
successful parsing/close. No failed Linux fallback, retry, cached observation,
new waiter, timer extension or changed group/receipt rule. Ordinary kernel-call
blocking limitations remain. Real Linux cases and exact-source CI are required;
local mocked/Darwin passes cannot close worker acceptance.

## 2026-10-11 — preserve compatibility while repairing ownership failures

**Decision:** retain current codec/planner behavior, both index-resolution calls,
and the existing decode, journal, fence, lease and transaction boundaries.
Repair only process-local ownership/reference registration cleanup. Attempt
every affected per-key restoration and preserve primary errors together with
cleanup faults; detach returned finalizer handles where available.

**Rationale:** matching final hashes does not establish equivalent reads,
exceptions, ownership or lifetimes for injected codecs and planners. No supported
behavior-preserving cost-removal design has been established. New adverse tests
demonstrate incomplete registry cleanup and lost cleanup errors in the original
issuance paths; the focused changes address those failures without changing
successful financial or persistence behavior.

**Validation and limits:** ordinary SQLite regressions pass with the three
PostgreSQL-only cases reported as skips. Those three cases also pass separately
on a newly owned disposable PostgreSQL 16 fixture, covering restart/retry and
deferred-commit rollback. This is not full concurrency-race, retained-history,
exact-revision Linux, genuine-source or Wave 4 acceptance. Arbitrary callback
effects and registered-but-unreturned finalizers remain outside the cleanup
guarantee. No financial/risk limit, lease, timer, native/seal mechanism or live
authorization is changed.

## 2026-10-11 — failure-only native deadline location metadata

**Decision:** the test diagnostic may bind the unchanged native Linux observer
and its one immediate deadline-check code, then transiently inspect at most8
traceback frames after the original ending clock sample. Admit only an exact
TimeoutExpired with one adjacent known pair and a0–4095 line offset after a
complete bounded scan. Binding inspects at most32 constants. Clear failed
bindings and the temporary exception reference; keep only static code identities
and scalar metadata. Unknown cases preserve the legacy summary shape.

**Rationale:** public1382752 shard3 reports an observation timeout but its aggregate
213556818ns does not identify the rejecting check. Finite Source review finds no
demonstrated compatible production bug. Meaningful oracles distinguish original
check locations, finally-moved frame state, foreign/subclass errors, bounds,
metadata faults and immediate error/payload release. A failed preparation
regression demonstrated why clearing the local exception is necessary.

**Consequences/constraints:** this identifies rejection location only. It cannot
attribute delay or grant source/trading authority. No production code, clock,
100ms deadline, retry, ownership/cleanup, financial assertion or risk limit changes.
Preserve completed original CI before selecting a new exact-source location
question; no blind retry or consumed-study replay. Local52 diagnostic passes and
270 process passes/3 Linux skips do not qualify real Linux worker acceptance.

## 2026-10-11 — test-only two-iteration lifecycle forwarding output

**Decision:** use two caller-owned scalar recorder slots and a free wrapper around
an already-constructed lifecycle probe. Preserve original dynamic forwarding,
arguments/results/errors; new setup faults return the original delegate.

**Rationale:** the failed903438b worker reports probe_stalled before any child
observation, and the existing test performs two iterations. Separate scalar
snapshots can identify an unfinished attempted forwarding boundary without
retaining private probes/inputs/errors or claiming SQL entry or delay cause.

**Consequences/constraints:** setup is single-threaded, snapshots have no global
atomic epoch, and unavailable/missing metadata is unknown. A compact ASCII line
includes prefix/LF within4096B, follows the unchanged child diagnostic and attempts
one guarded dynamic stdout write with no retry. Original assertion and financial
checks/cleanup remain authoritative. Inert wiring uses a pinned original Source
oracle and fake ports; no real account/worker or financial acceptance follows.
No production, lease, observer, risk or trading-authority change is made.

## 2026-10-11 — preserve Stop assertions while exposing returned scalars

**Decision:** wrap only the four later parent-fault assertions, retaining the
initial receipt/status assertion outside. On failure, admit the exact existing
frozen/slotted outcome class before inline status/reason reads, then call a
test-only scalar fixture. Guard new metadata faults and bare-rethrow the original
assertion. No caller aliases/holders, phase history or normal-pass output.

**Rationale:** exactf64194a CI fails before observing the Stop case's leased
trigger, while returned status/reason and flags are unprinted. This does not
prove a Stop priority defect. The helper's exact native gates are still required
because frozen dataclass annotations do not enforce field value types. Strict
raw JSON pair admission prevents duplicate keys concealing private text.

**Consequences/constraints:** one compact ASCII4096B line including prefix/LF,
prepared before one guarded dynamic write, no retry/flush. Post-return samples
are independent, missing fields unknown, and original cleanup/error identity
remain authoritative. Full golden-module normalization and inert adverse/private/
lifetime controls qualify wiring only. Check configured imports in final file
locations: scratch formatting/lint alone missed first-party grouping. No product,
production, lease/deadline, risk/authority or financial acceptance change follows.

## 2026-10-11 — release suppressed outcome-diagnostic tracebacks

**Decision:** discard the complete traceback of an auxiliary exception suppressed
by the scalar diagnostic, including any preexisting traceback. Use the native
BaseException descriptor without calling custom exception hooks. If a metadata
callback raises the exact pending primary exception, protect its entry traceback
instead. Do not inspect or mutate causes, contexts or arguments.

**Rationale:** the first combined129-case offline run failed two baseline lifetime
checks. A separate stdlib-only probe confirmed that a retained metadata traceback
links its helper frame to caller locals through frame.f_back; clearing helper
inputs alone does not release that edge.

**Consequences/constraints:** auxiliary traceback history is intentionally lost;
only bounded scalar output is diagnostic evidence. The original assertion's
identity, entry traceback, cause and context remain authoritative. Retain the
baseline lifetime oracle and add adverse callback/preexisting-error controls.
Implementation and fresh149-case validation plus independent Source/result/
archive/public-diff review pass; final document/staged checks remain in STATUS. This applies only
to the test-only scalar emitter, not production exception handling or every
other diagnostic fixture; no universal resource/replaced-primitive recovery.

## 2026-10-11 — extend qualified traceback cleanup to worker output

**Decision:** use the qualified native traceback cleanup policy only in the
worker failure-line emitter. Discard admitted auxiliary traceback history,
including preexisting history; restore the exact pending primary's entry
traceback without custom attribute hooks or cause/context mutation. Failed
primary admission leaves output and cleanup unknown. Preserve single-write
behavior, fallback policy and all other helper functions.

**Rationale:** the separate64-case witness passes all55 old controls and fails
six caller-local lifetime and three pending-primary traceback cases. These are
actual inert emitter failures. The same small cleanup helper is already
qualified for the Stop scalar diagnostic; reuse its established policy without
introducing a new fixture dependency.

**Consequences/constraints:** retain all64 case identities and literal lifetime
oracles; the old retained auxiliary-write traceback expectation now reflects
explicit discard. Add eight preexisting/hostile-hook/unadmitted-primary controls.
Source, architecture, statics and fresh110-case validation pass; independent
result/all20 archive inverse reviews pass.
Constructor/snapshot issuance faults outside this emitter remain unchanged and
unqualified. Production error handling, worker assertions, financial behavior,
timing limits and execution authority remain outside this repair.

## 2026-10-11 — extend metadata traceback recovery to four setup/snapshot hooks

**Decision:** admit the pending primary and native entry traceback before manager,
recorder, wrapper construction and recorder snapshot work. Reuse the existing
native cleanup only after successful admission; discard complete auxiliary
history, restore the exact pending primary's entry traceback, and release
temporary references in finally. Original delegate construction stays outside
recovery. No cause/context/args traversal or custom exception hook invocation.

**Rationale:** the separate122-case witness exposed eight caller-local lifetime
and four same-primary entry-traceback failures while all110 prior controls passed.
Later primary cause/context/args checks were unreached at the failed assertion.
The established emitter cleanup addresses the same retained traceback edge.

**Consequences/constraints:** intentional auxiliary history discard extends to
these four test-only metadata hooks. All84 case identities and literal lifetime
oracles remain; one prior auxiliary-constructor traceback expectation now matches
the explicit policy. Twenty adverse controls and fresh142-case validation pass
with independent Source/result/archive review. Production handling, original
delegate exceptions, financial behavior, timer/resource limits and execution
authority remain outside scope; no universal recovery guarantee follows.

## 2026-10-11 — preserve wire identities while shortening string-pair encoding

**Decision:** emit the existing typed JSON directly for nested exact two-element
tuples whose members are both exact strings. Keep separate dynamic ASCII-encoder
lookups and left-to-right formatting; other shapes keep the original path. There
is no cache, financial-check reduction, altered clock, lease renewal or limit change.

**Rationale:** the existing failed restore profile identifies repeated canonical
encoding as a hotspot. New independent-oracle synthetic comparisons preserve
bytes and avoid recursive pair visits. Pair-heavy and mixed-record medians
improve; nonpair tuples regress2.62% in a noisy finite comparison, so no universal
performance or overall lease-fit claim follows.

**Consequences/constraints:** retain byte/hash, escape, enum/subclass, deferred-hook,
first-error, class-lifetime and exception-identity oracles. Local467-case validation
passes including the eight original retained/proof cases with real60s leases.
Exact-revision Linux financial acceptance and all source/account/session/initializer
gates remain separate. See the [repair record](reviews/2026-10-11-restore-string-pairs/README.md).
