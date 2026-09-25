# Wave 4 B coordinator/risk preflight

Read-only proposal against `adf39a99d3717d6800186dabd532399534bfe65c`; implementation starts only after verified W3 merge and root interface freeze. No provider calls, tests, repository edits, deployment, order authority or re-arm are part of this review. The canonical plan §8 remains the scope; W1 account eligibility amendment `/2` permits explicit CASH/MARGIN privileges under `cash-funded-long-only/1`, without treating margin buying power as cash.

## Recommended integration

Add one bounded coordinator application service around the existing causal engine and account transaction, not another decision engine. Its `advance(work: CoordinatorWork) -> CoordinatorResult` consumes one root-defined durable event/command. Root owns causal-engine continuation/checkpoint composition; A owns applied reconciliation; C owns independently persisted simulated venue/source observations. B supplies a versioned runtime risk producer and atomic decision/capacity integration. All assignment and outbound-work contracts explicitly identify `stateful_simulation`; connected observations may explain blockers but cannot acquire order authority.

Reuse `evaluate_daily_risk` as the canonical arithmetic entry. Preserve its W2 inputs, hashes, exceptions and engine-only producer behavior. Root should freeze an additive runtime-evidence variant and policy `personal-daily-stateful-simulation/1`, with producer map `personal-daily-runtime-producers/1`; do not pass runtime facts under a fabricated `producer.name == "engine"`. A narrow version dispatch can share the existing reservation/exposure arithmetic while retaining historical validation unchanged. The existing engineering caps remain; no live policy assignment is created.

## Implemented pieces and exact gaps

| Existing implementation | Reuse and boundary |
|---|---|
| `domain/daily_risk.py:31`, `domain/engine_contracts.py:32,393` | All-or-none cash/share reservations, pending-buy exposure, no sell-receipt funding, loss/count/expiry gates. Evidence currently requires the engine producer and contains simulation booleans, not independently bound runtime receipts. |
| `domain/accounting_contracts.py:193`, `backtest/personal_accounting.py`, `domain/wealth.py:205` | Authoritative nullable-NAV account projection and flow-neutral arithmetic. Reuse quantities, fees, settlement/payables and wealth lineage; do not add another ledger or loss calculator. Engine wealth/accepted-ID/request-budget state is currently per-run (`application/causal_engine.py:820–854`) and needs a durable continuation checkpoint. |
| `persistence/account_coordinator.py:834,1030,1102` | Exact generation/lease history and caller-transaction fence revalidation; expired ownership already rejects automatic takeover. Lease authority presently samples its injected `Clock`, not necessarily transaction database time. Root must pin an explicit runtime DB-time mode while preserving historical clock semantics. Lease expiry never proves old-process termination. |
| `persistence/batch_risk.py:2423,2450,2462,2486` | Authentic active-capacity universe, observation sequence, retry lookup and transaction-level persistence helpers. These require Phase-2 `BatchRiskDecision`/snapshot/limits; they cannot directly persist W2 `DailyRiskDecision`. Existing old-policy enforcement gates remain binding. |
| `persistence/advanced_batch_risk.py:321,2167` | Useful pattern: materialized transaction-bound producer input, current control/assignment checks and atomic admission. Reuse the pattern, not historical intraday/SIP policy assumptions or authority tokens. |
| `persistence/operational_control.py:977,1028,1413,1429` | Authenticated control-chain read/application and explicit re-arm path already exist. A durable REQUESTED→APPLIED consumption seam for the new coordinator must join the same account transaction; ordinary `apply` must continue rejecting raw re-arm. |
| `persistence/submission_attempt.py:1705,1886,1983,2004` | Existing approval consumption, PENDING/IN_FLIGHT, exact fence, UNKNOWN freeze and immutable outcomes remain authoritative. `prepare` requires the old batch decision; new daily admission needs a root-owned versioned bridge. UNKNOWN resolution still unconditionally rejects. |
| `persistence/reservation_lifecycle.py:2752,2846,2976` | Unsent expiry and accounted execution release are reusable; sent terminal release still rejects without durable reconciliation. Do not substitute backtest horizon finality or equal/empty snapshots for A's accepted evidence. |
| `persistence/broker_request_budget.py:704` | Durable purpose-specific permits and shared account serialization exist. Issuance owns a separate transaction; root must expose a same-transaction seam if permits are part of admission/claim. Simulation quotas never certify actual E*TRADE quotas. |

## Versioned producer map

Every runtime item binds account/environment, producer version, immutable evidence digest, source/receipt times, coverage and current revision. Missingness stays UNAVAILABLE; projection time cannot refresh old provider evidence.

| Daily-risk input | Authoritative runtime producer / acceptance |
|---|---|
| Account scope, financing, strategy, instruments | Root assignment + A qualified binding/restrictions; preserve actual CASH/MARGIN mode. Unknown USD, liability, calls or usable-cash semantics blocks exposure. |
| Cash, shares, pending commitments | A-applied canonical ledger + authenticated capacity universe under the account lock. `settled_cash - executed buy payables - restrictions - still-unfilled holds`; never count a fill as both payable and unfilled hold. Include old-policy UNKNOWN/pending-cancel commitments. |
| Daily input/session/trigger | C immutable admitted source + root calendar/causal scheduler and durable trigger IDs. Preserve 20:00 decision, 09:00 cutoff and 09:35-inclusive/09:40-exclusive activation; skip missed triggers. Historical next-open proxies cannot attest forward quotes. |
| Quotes/marks/reconciliation | C source/account entitlement and actual source/receipt timestamps; A applied reconciliation ID plus covered ledger/effect watermark. Enforce quote age <5s, receive-to-check <1s, dispatch projection <5s and reconciliation <60s with no later unresolved effects. |
| Daily return/drawdown | Same engine wealth reducer, persisted flow pairs, previous-close wealth and running peak. No reset on restart, contribution, policy change or re-arm; missing current marks/history blocks. |
| Distinct accepted intent IDs / request capacity | Durable session acceptance registry across terminal outcomes/retries, plus purpose-specific permit history. Preserve four outstanding/one per symbol/eight newly accepted IDs and simulation 20/60s total, 10 low-priority; reserve observation/cancel capacity. |
| Controls/ownership/time/session | Current control and assignment heads; exact process/lease generation; W1 clock-health history and monotonic age; A/C environment-specific session readiness. Automatic incidents only tighten controls. |

## Atomic boundary and root contracts needed

`SqlDailyAccountRiskRepository.authorize(batch: DailyIntentBatch, fence: AccountFence, *, input_refs: RuntimeRiskInputRefs) -> RuntimeRiskAdmission` should use one account-serialized transaction. Load/verify exact command or batch retry first; matching retry returns its retained result, never renewed dispatch authority. Read current lease, control, assignment, A ledger/reconciliation heads, capacity, trigger/count and permit revisions; derive an immutable snapshot/evidence bundle; evaluate; atomically append the full accepted/rejected decision, holds and bounded outbound work/command acknowledgement. Revalidate time/fence and relevant revisions before commit. No provider/strategy subprocess I/O occurs under the SQL lock. A later single-use send claim separately revalidates current controls/fence/validity; a previously committed claim remains uncertain after pause, not retroactively unsent.

Root must freeze these shared seams before consumers:

1. Runtime evidence/assignment/admission DTOs with policy, producer, account-binding, ledger/mark/settlement/commitment/control/reconciliation/lease revisions and explicit all-false live authority; stable IDs and per-rule source/result rows.
2. One capacity representation joining preserved old holds with new daily approvals; a versioned submission-preparation bridge that actually authenticates daily decisions. Never coerce a daily decision into legacy evidence just to satisfy an exact-type check.
3. Caller-owned transaction seams for command consumption, permit reservation, attempt preparation/claim and A-applied reconciliation releases. Root retains `submission_attempt.py`, serialized order/ledger/control contracts and all migrations.
4. Durable canonical-engine continuation: strategy state, event frontier, consumed/skipped triggers, accepted intent IDs, wealth/previous-close peak, request history and pending due work. Root owns the engine step/checkpoint API; B does not inspect a future tape.
5. Paused policy cutover receipt: exact old/new assignment and all obligation identities, no unresolved unenumerated effects, fresh reconciliation, and explicit later owner re-arm. Preserve old policy bindings and drawdown/count history. Missing old-worker termination evidence keeps ownership/restart blocked.

## Proposed exact non-shared lane-B allowlist after freeze

Production: new `packages/application/account_coordinator.py`; new `packages/application/daily_risk_snapshot.py`; new `packages/persistence/daily_account_risk.py`; narrowly scoped `packages/domain/daily_risk.py`; narrowly scoped `packages/persistence/account_coordinator.py` for the root-approved database-time authority mode only.

Tests: new `tests/unit/test_daily_runtime_risk.py`; new `tests/unit/test_daily_risk_snapshot.py`; new `tests/integration/test_daily_account_risk.py`; new `tests/integration/test_personal_account_coordinator.py`.

Existing batch-risk/reservation/control/attempt/assignment implementations are read-only dependencies initially. Any transaction adapter edits there require a separate exact root assignment; no directory-wide ownership. Root also owns shared DTOs, schema/migration head, canonical engine, codec/readers, composition, CI and docs. A/C retain reconciliation/venue/source files.

Focused acceptance: W2 semantic parity; each absent/stale/future producer; both financing modes without inferred cash; reservation/payable overlap and mixed old/new holds; duplicate/late/corrected fills; UNKNOWN/pending-cancel preservation; pause-versus-claim and policy-cutover races; two real PostgreSQL coordinators contending for capacity; rollback across every participating table; restart preserving peak/count/trigger state; stale-generation rejection and no auto-rearm. Root integrates the independent venue/session replay and actual PostgreSQL gate. None is executed or claimed by this preflight.
