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
