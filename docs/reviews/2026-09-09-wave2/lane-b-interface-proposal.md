# Wave 2 lane B: execution and accounting interface proposal

Status: proposed, not frozen or implemented. Inspected base:
`ec63ca793ed4fe8a68397dc752000e102741da59`, branch
`codex/personal-v1-w2-accounting`. The active canonical plan section 17 and
`docs/reviews/2026-09-09-wave2/README.md` supersede this checkout's historical
W1 handoff. This document is the lane's only initial deliverable. W0 contract
bytes, historical reducers and W1 evidence remain unchanged.

## 1. Recommended boundary

The application causal engine owns the only event queue, ordering frontier,
callback microcycle, clock, activation sequence and scheduling operation. Lane B
provides one pure transition over one admitted command; it never receives or
searches a future tape. Root owns and freezes the shared DTOs before consumers.
The following names and fields are a concrete proposal for that freeze:

```python
class ExecutionAccountingPort(Protocol):
    def advance(
        self,
        *,
        state: AccountingState,
        command: AccountingCommand,
        context: EngineReductionContext,
        policy: ExecutionAccountingPolicy,
    ) -> AccountingTransition: ...
```

All shared records are frozen dataclasses with tuples, finite Decimal amounts,
whole-share quantities, timezone-aware instants and explicit schema versions.
Neither implementation nor its inputs contain a provider client, wall-clock
function, mutable RNG, strategy callback, future input iterator or enqueue port.

| Record | Required immutable fields and ownership |
| --- | --- |
| `EngineReductionContext` | Run identity/hash; account/instrument scope; current envelope ID/hash; economic and knowledge instants; closed input-frontier ID/hash; engine reduction sequence; current session/window facts with calendar pins. Issued by A. |
| `AccountingState` | State revision/hash and predecessor; applied command ID/payload hashes; submissions, per-order broker events/cancel requests, activations and modeled terminal dispositions; shared commitment records; cash flows, splits, dividend accruals/payments, settlement instructions/confirmations and causal marks. Only facts admitted by the engine. |
| `ExecutionAccountingPolicy` | Versioned execution, fee/slippage, numeric, FIFO, financing, reserve-overlap, dated settlement and settlement-calendar pins. The root RunSpec owns these identities. Oracle policy is explicitly distinct from product policy. |
| `AccountingTransition` | Applied/duplicate/rejected disposition; predecessor/next state hashes; next immutable state; newly admitted fact IDs and canonical ledger-entry deltas; accounting projection and commitment projection; due-event descriptions; FIFO match lineage changes; optional cash-flow boundary pair; explicit valuation/eligibility limitations. No trading authority. |

`AccountingCommand` is a tagged union, with a stable command ID and payload hash:

1. Install an A-approved commitment and its `OrderSubmission`; activate that
   order with its engine sequence and activation/window facts. These are separate
   transitions where required by the engine stages. B does not issue risk approval.
2. Observe one `ExecutionObservation`: source ID/hash, instrument, source kind,
   reference price, economic/knowledge instants, frontier/sequence, session pins
   and provenance. An explicitly synthetic per-event quantity budget may be
   supplied by a pinned partial-fill model. No future bars or arbitrary OHLC
   fallback are present.
3. Apply one admitted `BrokerOrderEvent`, cancel request, or explicitly modeled
   terminal disposition. UNKNOWN is commitment uncertainty, not a fabricated
   broker status or an execution fact.
4. Apply one contribution/withdrawal, stock split, dividend accrual/payment,
   settlement confirmation, or causal mark. Existing exact constructors below
   remain the economic fact vocabulary wherever they fit.

A schedules returned `DueEventDescription` values, each carrying a deterministic
ID, parent fact ID/hash, due instant, policy/calendar pins and command payload.
For example, a fill returns its exact settlement instruction and a modeled due
confirmation description. Merely returning it changes no settled balance. A later
engine event must admit that confirmation. Dividend payment likewise needs an
explicit synthetic payment policy/fact; payable date alone is not proof of actual
provider payment. Equal due events deduplicate by ID and hash.

Exact duplicate command/fact payloads create no new economic postings or state
revision. A duplicate may have an engine audit receipt outside the economic state.
Same ID/different payload, wrong scope, stale predecessor, conflicting sequence,
unproven dependency or future knowledge fails the affected transition. Replay
reconstructs the same states and hashes; previously emitted historical snapshots
are not rewritten when a correction becomes known later.

## 2. Existing seams and concrete gaps

Paths and line anchors below refer to the inspected base, not proposed code.

| Existing seam | Reuse and boundary |
| --- | --- |
| `packages/domain/order_reducer.py:129,186,361,431` | Reuse `create_order_submission`, `BrokerOrderEvent`, `create_cancel_request`, `reduce_order_lifecycle`. Contiguous event sequences, exact duplicate handling and execution revision lineage already exist. There is no UNKNOWN, pending-cancel or EXPIRED enum; do not add them implicitly. |
| `packages/domain/ledger_reducer.py:120,439,503` | Reuse `create_cash_flow` and `reduce_execution_ledger`. Balanced immutable journal; execution corrections post deltas, and fees are expensed once. |
| `packages/domain/settlement_ledger.py:125,191,883` | Reuse `create_settlement_instruction`, `create_settlement_confirmation`, `reduce_settlement_ledger`. Every nonzero execution cash delta needs an exact instruction. The reducer takes explicit due instants; it does not implement dated calendars. It rebuilds the execution ledger and does not accept corporate-action cash. |
| `packages/domain/corporate_action_ledger.py:160,261,331,664` | Reuse `create_stock_split`, `create_cash_dividend`, `create_dividend_payment`, `reduce_corporate_action_ledger`. Entitlements derive from pre-effective holdings. Ambiguous simultaneous actions and unsupported fractional shares already reject. |
| `packages/domain/account_projection.py:614,706` | Reuse FIFO arithmetic and the initial execution time retained across corrections. The strict `project_fifo_account` requires a mark for every open position, reports trade-date cash and aggregate realized P&L, and exposes no consumed-lot match stream. A reusable unvalued FIFO result is needed so absent marks do not block cash/order state updates. |
| `packages/backtest/simulated_broker.py:452,877,1293` | Existing immutable execution terms are useful references. `ConservativeSimulatedBroker` owns/searches the full future tape, full-fills and uses source `close_price`. It cannot be the new one-observation causal port. Preserve its isolated historical tests. |
| `packages/backtest/simulation_horizon.py:51,168,617` | Existing request/horizon proofs bind the old full replay/reservation/attempt path. Do not synthesize a horizon proof from an empty current observation or reuse it to release UNKNOWN exposure. Preserve the old contracts. |

The intended implementation extracts FIFO mechanics once and delegates the old
strict projection API to that same implementation. Reporting must not reconstruct
a competing FIFO book. Existing public reducers stay strict and their historical
tests remain compatibility checks.

## 3. Eligibility, modeled fills and terminal commitments

An order must already be activated before the current observation's frontier and
engine sequence, and its activation instant must be strictly earlier than that
observation's economic instant. An observation that triggered the order cannot
fill it, including after an equal-frontier callback. Source identity, session,
window, instrument, unadjusted price basis and model pins must match. Missing or
ineligible observations retain the commitment; no fallback to a close, adjusted
price or later unobserved bar is allowed.

The frozen historical model is `next-regular-open-proxy-v1`, an exploratory
assumption. An open proxy is an explicitly identified source price event; it is
not evidence of a fill in the separately specified connected execution window.
The engine decides session/cutoff ordering and admits the observation. B checks
the passed facts and produces a deterministic candidate fill or a reason it cannot.

Base modeled costs are adverse 5 bps per side plus $0.01/share; stress costs are
20 bps plus $0.02/share, as frozen in W0. Proposed pure pricing is
`reference_price * bps / 10000`, added for buys and subtracted for sells, with
explicit pinned rounding/precision. There is no observed spread claim. The base
fixed fee is zero. A nonzero fixed-fee policy must say whether it is per order or
per fill and track the already charged portion; partial fills must not silently
charge a per-order fee repeatedly. Existing `SimulatedMarketOrderModel` uses fixed
per-share offsets, so it cannot silently stand in for this bps policy.

Partial fills use an explicit deterministic synthetic event quantity budget;
daily volume does not prove available liquidity. Default whole-order and optional
partial models have separate IDs. If one budget is shared by several orders,
allocation is deterministic over preexisting activation sequence then stable
order ID, and the budget is consumed once across that observation. B may traverse
the current immutable active-order set, but never a future event list. The initial
model needs no random draws; any later RNG requires a pinned algorithm, seed and
draw identity in the root contract.

Effective target quantity is filled quantity plus unresolved buy commitments
minus unresolved sell commitments. Approved-unsent, UNKNOWN, working, partial and
cancel-pending commitments count. Opposite targets cannot erase uncertainty.
Cancel requests release nothing. A fill reduces the covered remaining commitment
and records its payable/receivable atomically. A confirmed cancellation or rejection
releases only its authoritative remaining quantity; late execution facts still
update actual economics. A fresh target after cancellation requires a new intent
and activation; it cannot fill from its own trigger.

`CanonicalOrderState.remaining_quantity` is original minus filled even after
CANCELED. E7's terminal remainder is therefore 2 in the old arithmetic property,
but its held commitment must be 0. The shared commitment projection must use both
remaining quantity and terminal/uncertainty evidence. It must not modify that old
property or infer release from an elapsed timeout. A correction/bust can change
the old reducer's derived status; that does not prove broker reopening or authorize
reactivation. A root-defined modeled terminal disposition is preferable to calling
DAY expiry a fabricated owner cancellation. Its release semantics must be frozen.

## 4. One cash and reserve projection

Let `E` be execution-ledger trade-date cash, `C` corporate-action-ledger cash, and
`D = C - E` the corporate-action cash delta. At the present supported action scope,
`D` includes admitted dividend payments; contributions are already included in E.
Let `S`, `R`, `P` be the settlement reducer's settled cash, outstanding trade
receivables and outstanding trade payables. Let `DR` be dividend receivables.
The authoritative combined projection is:

```text
trade_date_cash              = C
settled_cash                 = S + D
trade_receivable             = R
trade_payable                = P
dividend_receivable          = DR
available_before_open_holds  = settled_cash - P
available_for_new_orders     = available_before_open_holds
                              - remaining_buy_hold - sell_fee_hold - other_hold
NAV                         = settled_cash + R - P + DR + marked_market_value
                            = C + DR + marked_market_value
```

Do not sum the two complete base ledgers. Journal entries merge by immutable entry
ID/hash, and transition output contains only newly admitted entry deltas. Payment
reclassifies dividend receivable to cash without a second income posting. Trade
settlement likewise creates no profit. Receivables and margin buying power never
fund new cash-funded orders. Any negative cash/capacity or financing uncertainty is
an explicit limitation; the arithmetic is not a qualification for borrowing.

One shared commitment record owns a reservation per intent; the same broker order
must not add a second hold. Its buy hold is remaining quantity times the approved
worst-case execution price plus its remaining explicit fee budget. A fill replaces
the covered hold portion with actual payable/cash, rather than retaining both.
UNKNOWN without fill evidence retains the full worst-case unresolved hold.

A supplemental synthetic overlap test, not an added W0 fact: quantity 5, approved
maximum price 102 and total fee cap 3 reserve 513. A fill of 2 at 100 plus fee 1
leaves payable 201 and hold 308, giving available capacity 491 from opening 1000.
A late fill of 1 at 102 plus fee 1 leaves payable 304 and hold 205, still 491.
Confirmed cancellation releases 205, giving 696. This test requires an explicit
fee-budget policy and exact hold lineage. E7 itself fixes no such reserve amount.

Accounting facts, lots and commitments advance even when valuation is unavailable.
The shared account projection needs nullable authoritative market value/NAV with
reason and mark coverage/freshness metadata. A last-known estimate, if requested,
is separate and carries age; it cannot be substituted into risk or exact return
statistics. The old strict projection API may continue raising for missing marks.

## 5. Settlement calendar and dated policy

Use the already frozen W0 dates; no new external facts were fetched for this
proposal. Policy `dated-us-equity-standard-settlement-v1` selects T+3 before
2017-09-05, T+2 from 2017-09-05 through 2024-05-27, and T+1 from 2024-05-28.
Select the nth settlement business date strictly after the execution's local
trade date. Modeled cash release is 09:30 America/New_York on that date, explicitly
an assumption, not an observed broker credit time.

`SettlementBusinessCalendar` needs ID, version, content hash, timezone/tzdata pin,
covered date interval and an immutable set/tuple of business dates. It is a
separate input from the exchange-session calendar; do not alias them or synthesize
holidays from weekends. Missing required coverage fails scheduling. A engine-owned
due event calls `create_settlement_confirmation`; the clock reaching a due date
alone does not mutate B state.

Boundary fixtures can specify these dates explicitly without claiming a researched
historical calendar: a 2017-09-01 trade with next eligible dates Sep 5/6/7 yields
Sep 7 under T+3; Sep 5 yields Sep 7 under T+2. A 2024-05-24 trade with next dates
May 28/29 yields May 29 under T+2; May 28 yields May 29 under T+1. Also include a
fixture date that is an exchange session but absent from the settlement calendar,
plus calendar coverage exhaustion and DST conversion checks. Production historical
labels require a root-approved pinned calendar source, not these synthetic lists.

Every nonzero correction cash delta needs its own exact settlement instruction.
Existing instructions require due time at or after the correction's occurred time;
an original settlement date already in the past cannot simply be copied. W0 does
not fix the later-correction due-date convention. Root must freeze an explicitly
modeled correction/bust settlement rule or supply explicit dated oracle instructions.
Opposing pending obligations cannot be netted into immediately available cash.
The E6 cash checkpoints are trade-date economics, not automatic settlement release.

## 6. Outputs required by reporting

The shared immutable FIFO result must expose open lots and `RealizedMatch` lineage:
buy execution/order IDs and revision, sell execution/order IDs and revision,
matched whole quantity, released basis, proceeds, gross realized P&L and supporting
fee facts. The existing FIFO rule retains the original execution acquisition time
when its price/quantity is corrected. A correction emits a replacement/retraction
link to prior match hashes; reports must not sum obsolete and replacement matches.
Fees remain expensed once in the journal. Allocating a fee across matches for trade
statistics is report attribution, not another expense. Root/C must pin exact
rational allocation or rounding for nonterminating allocations before implementing
net match statistics.

For every external flow, B returns before/after projections under the same admitted
mark set and its hash, flow ID/hash, signed amount and the state hashes bracketing
the flow. A issues the actual pre/post engine sequence and frontier pair; reporting
consumes that engine-issued boundary, never reconstructs one from end-of-day data.
When both NAVs are defined, `NAV_after = NAV_before + signed_flow`. Missing causal
pre-flow valuation leaves the exact flow pair/TWR undefined with its reason; neither
lane may look ahead for a replacement mark. C owns return/benchmark arithmetic.

## 7. Independent W0 constructor probes and acceptance map

The following probes were executed locally against existing reducers, using
independent literal synthetic inputs, not old test fixture constructors. Decimal
assertions matched the W0 `economics-cases.json` checkpoints. This is feasibility
evidence for reuse, not a pass of a new causal engine or shared interface.

Common construction: `DecisionTrigger` and `OrderIntent` with explicit synthetic
identity/hash fields; `create_order_submission`; ACCEPTED and EXECUTION
`BrokerOrderEvent` values with contiguous sequences; `create_cash_flow` contribution
1000; `create_position_mark`; and the order, execution-ledger, settlement and FIFO
reducers. All source identities in the probes are synthetic. E1's opening buy is
2024-06-03; explicit fixture confirmations are June 4 and June 6 at 13:30 UTC.
These supplied due instants test existing reducers, not the absent calendar policy.

| W0 case | Exact constructors and observed checkpoints | Remaining integration acceptance |
| --- | --- | --- |
| E1 | Buy 4 at 100 fee 1: `reduce_execution_ledger`, `create_settlement_instruction`, `reduce_settlement_ledger`, `project_fifo_account` give trade cash 599, settled 1000, payable 401, available 599, basis 400, NAV 999. `create_settlement_confirmation` gives settled 599/payable 0. Sell 2 at 110 fee 1 gives trade cash 818, settled 599, receivable 219, available 599, basis 200, gross realized 20, total fees 2, net realized 18, unrealized 20, NAV 1038. Sale confirmation gives settled/available 818, receivable 0, unchanged NAV. | Engine schedules confirmations and exposes current buckets to next callback; neither close fills nor sale receivables finance a new buy. |
| E2 | Opening funding 1000 and fee-free buy 4 at 100 construct cash 600/basis 400. `create_cash_dividend` for pre-effective quantity 4 at 2/share and mark 98 gives receivable/income 8, cash 600, MV 392, unrealized -8, NAV 1000. `create_dividend_payment` gives cash 608/receivable 0/income still 8/NAV 1000. | Unified settled-action cash formula; engine pre-effective entitlement and actual payment event; ex-date buyer excluded. |
| E3 | Same opening. `create_stock_split` 2-for-1 on entitled 4 and later mark 50 gives quantity 8, basis 400, NAV 1000. Sell 3 at 55 fee 1 gives cash 764, quantity 5, basis 250, MV 275, gross realized 15, fees 1, net realized 14, unrealized 25, NAV 1039. | Preserve per-lot split lineage and report consumed FIFO matches; no invented split profit. |
| E6 | Same execution ID, EXECUTION_CORRECTION revision 2 with exact predecessor, quantity 4/price 101/fee 2 changes cash 599 to 594, basis 400 to 404, fees 1 to 2, NAV at 101 to 998. Exact duplicate yields equal ledger/no new economic postings. Revision 3 quantity 0, positive reference price 101 and explicit fee 0 yields cash/NAV 1000, quantity/basis/fees 0. | Engine preserves pre-correction knowledge snapshots; correction/bust due policy and report replacement lineage. Fee 0 is explicit synthetic refund evidence, never inferred from a broker bust. |
| E7 | Original quantity 5, fill 2 at 100 fee 1 gives cash 799, filled 2/arithmetic remainder 3. `create_cancel_request` retains remainder 3. Late distinct execution of 1 at 102 fee 1 gives cash 696, quantity 3, basis 302, fees 2, NAV 1002 at 102. CANCELED event leaves canonical arithmetic remainder 2. | Shared held remainder becomes 0 only on confirmed cancellation. A repeated target before confirmation emits no new intent; fresh target afterward emits 2 and cannot consume its trigger. UNKNOWN and reserve-overlap cases must be added. |
| E8 | `create_stock_split` rejects unsupported fractional 3-for-2 on one share. Split and dividend at the same effective time reject as ambiguous. `project_fifo_account` rejects a held position without a causal mark. | New unvalued state continues accounting while authoritative NAV is undefined. Same-session freshness, missing pre-flow valuation, zero variance and sample thresholds require A/C integration tests; they were not established by these probes. |

Baseline regression command (no code or tests were edited):

```sh
env -i PATH=/usr/bin:/bin \
  PYTHONPATH=/Users/spencer.karrat/Documents/AutoQuantTrader/wave-worktrees/personal-v1-w2-accounting \
  PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /private/tmp/aqt-wave0-f152ahl7/venv/bin/python -m pytest \
  -p no:cacheprovider --basetemp=/private/tmp/aqt-w2-accounting-proposal-20260909 \
  tests/unit/test_order_reducer.py tests/unit/test_ledger_reducer.py \
  tests/unit/test_account_projection.py tests/unit/test_settlement_ledger.py \
  tests/unit/test_corporate_action_ledger.py tests/unit/test_simulated_broker.py \
  tests/unit/test_simulation_horizon.py -q
```

Result: **119 passed in 0.94 seconds**. The independent probes also passed their
assertions; their numeric checkpoints are recorded above. No provider, credential,
network, persistence migration, order submission or deployment was used.

Future tests must additionally exercise malformed/conflicting duplicate facts,
strict prior activation and equal-frontier denial, one-observation budget sharing,
partial/cancel/UNKNOWN holds, fees charged once, corrections after settlement,
separate-calendar boundaries, missing/stale marks without lost accounting state,
flow pair identity, and match revision lineage. Root's integration acceptance adds
both configurable strategies on both long labelled datasets, deterministic replay,
future-row prefix invariance and changed next-callback account/commitment state.

## 8. Proposed future exclusive files and root decisions

These are requested ownership slots, not current permission to edit them:

- New `packages/application/execution_accounting.py`: pure transition composition,
  no queue or engine entry point.
- New `packages/backtest/causal_execution.py`: one-observation modeled execution
  and explicit bps/fee computation, without the old broker's future-tape coupling.
- New `packages/domain/settlement_schedule.py`: pure dated scheduling over the
  root-frozen calendar/policy DTOs.
- New `packages/domain/fifo_projection.py` and a narrow extraction in existing
  `packages/domain/account_projection.py`: one reusable unvalued FIFO/match
  implementation, preserving the existing strict public projector.
- New `tests/unit/test_execution_accounting.py`,
  `tests/unit/test_causal_execution.py`, `tests/unit/test_settlement_schedule.py`,
  `tests/unit/test_fifo_projection.py`; narrow compatibility additions to
  `tests/unit/test_account_projection.py` if the extraction requires them.

Root retains shared DTO/schema modules, RunSpec identities, commitment/risk
contracts, strategy/report compatibility, fixtures/dataset conversion, migrations,
CLI/composition, the only causal engine's integration and golden/CI cutover. No
changes to the old simulated broker/horizon, order/ledger/action/settlement public
contracts are requested by this proposal.

Freeze decisions needed from root:

1. Shared DTO module and exact command/state/result shapes, including nullable
   authoritative valuations, commitment ownership, and explicit disposition errors.
2. The combined cash formula and reserve-overlap authority above; hold fee budgets
   and terminal/UNKNOWN/bust rules must be identical in A's risk projection.
3. Dated calendar identity/source/coverage, timezone pin and later-correction
   settlement policy. Do not silently claim a synthetic calendar is historical fact.
4. Bps numeric rounding, fixed/per-fill fee treatment, optional synthetic partial
   model and modeled DAY-expiry terminal representation.
5. The single FIFO extraction and versioned match/replacement DTO, including fee
   attribution precision required by C, without a second accounting algorithm.
6. A-issued pre/post-flow boundary sequencing and hash fields, and rejection versus
   undefined-valuation propagation for missing marks/dependencies.

These decisions enable implementation; the proposal does not itself freeze them
or satisfy the Wave 2 exit gate.
