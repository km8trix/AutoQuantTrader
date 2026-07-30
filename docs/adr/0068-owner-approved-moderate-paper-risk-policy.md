# ADR 0068: owner-approved moderate paper risk policy

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0067 deliberately stopped before assigning thresholds, windows, source
authorities, or breach actions to the Phase 5B measurements. The owner has now
approved a moderate envelope for the exact paper-only v1 scope: one cash
account, regular-hours, long-only, whole-share `DAY` market orders in DIA, IWM,
QQQ, and SPY. That approval is sufficient to freeze an immutable policy and
implement its evaluator and persistence. It is not an authenticated assignment
of the policy to an account, evidence that its runtime sources exist, or paper
trading authority.

The policy must also preserve the already durable Phase 2 batch-risk decision
and Phase 5A operational-control contracts. Rewriting either semantic payload
would invalidate retained decisions or control history. A separately persisted
assessment and admission sidecar can compose the approved policy without
reinterpreting those facts.

The source review provides design context, not numerical authority:

- The SEC's
  [Market Access Rule FAQ](https://www.sec.gov/rules-regulations/staff-guidance/trading-markets-frequently-asked-questions/divisionsmarketregfaq-0)
  describes automated pre-trade controls and says selection of particular
  credit or capital thresholds requires documented business judgment. It does
  not prescribe any percentage or basis-point value used here, and this
  application does not claim broker-dealer compliance.
- [FINRA Rule 4210](https://www.finra.org/rules-guidance/rulebooks/finra-rules/4210)
  governs margin requirements. It is not permission to add margin to this
  cash-only account model; leverage above one remains an anomaly detector.
- [Investor.gov's diversification definition](https://www.investor.gov/introduction-investing/investing-basics/glossary/diversification)
  explains the general rationale for spreading investments. It does not endorse
  the concentration percentages below.
- Alpaca's
  [paper-trading documentation](https://docs.alpaca.markets/us/docs/paper-trading)
  says the simulation omits market impact, information leakage, latency
  slippage, queue position, price improvement, regulatory fees, and dividends.
  Paper observations therefore cannot establish live execution quality.
- Alpaca's
  [real-time stock-data documentation](https://docs.alpaca.markets/us/docs/real-time-stock-pricing-data)
  defines quote bid, ask, size, condition, event-time, tape, and feed fields.
  The schema alone does not prove consolidated coverage, entitlement, freshness,
  or admission.

Every number in this ADR is an owner-chosen engineering policy for this exact
paper scope. No regulator, broker, or data vendor supplied or approved it.

## Decision

### 1. Scope and lifecycle

1. Define one content-addressed policy,
   `phase5b-moderate-paper-rth-etf-v1`, for environment `paper` and the exact
   sorted instrument set `US-ETF-DIA`, `US-ETF-IWM`, `US-ETF-QQQ`, and
   `US-ETF-SPY`. The scope excludes extended hours, margin, shorting,
   fractional shares, options, futures, crypto, leveraged or inverse ETPs,
   single-stock ETPs, and every live account.
2. A changed instrument set, calculator, source schema, source authority,
   threshold, comparator, window, action, Decimal policy, or classification
   creates a new policy version and digest. A paper policy is never promoted
   into live by changing an environment field or database assignment.
3. Owner approval means the policy may be represented and implemented. Runtime
   activation requires a separate authenticated, account/environment-bound
   assignment under an exact-head compare-and-set. Migration creates no
   assignment, absence fails closed, and assignment cannot be inferred from
   policy registration, process startup, configuration presence, or an
   observation.

### 2. Shared comparison, time, and completeness rules

1. All percentages, basis points, prices, values, ratios, aggregates, and
   thresholds use the repository's pinned context-independent `Decimal`
   arithmetic and exact persisted-value bounds. Binary floating point has no
   policy role.
2. A magnitude equal to a maximum limit remains within that limit. In
   particular, a value at the pause ceiling receives no pause, and a value at
   the halt ceiling receives the pause action rather than halt. The generic
   bands are:

   - `value <= pause_limit`: no runtime breaker action;
   - `pause_limit < value <= halt_limit`: `PAUSED`;
   - `value > halt_limit`: `HALTED`.

3. A trailing time window is left-open and right-closed:
   `(observed_at - window, observed_at]`. An event exactly at the old boundary
   is excluded. Freshness and expiry are authority windows rather than
   magnitude limits: evidence must satisfy `age < maximum_age`; equality is
   stale and grants no authority.
4. Only `COMPLETE` evidence produces a numeric rule result. `INSUFFICIENT`,
   `UNAVAILABLE`, and `OVERFLOWED` never carry a substitute value or pass.
   Required incomplete evidence rejects an exact proposed new-exposure batch
   and, in a deployed supervisor, requests `PAUSED` through the applicable
   source/data-health breaker. It is not misreported as a numeric loss,
   volatility, spread, slippage, or reject-rate breach.
5. All observations bind account, environment, policy assignment, producer
   identity/version/authority, exact causal sources, source availability,
   window, observation time, and recording time. A source revision never
   silently changes a retained observation.

### 3. Action semantics

1. `REJECT` is hypothetical-only. It denies the exact proposed new-exposure
   batch before reservation, authorization, or broker I/O. It does not write an
   operational-control transition. A rejected hypothetical exposure cannot
   pause or halt an account.
2. `PAUSED` and `HALTED` are runtime actions over current or already committed
   facts. They append Phase 5A `TRIP` commands in the same account transaction
   as the breached assessment. Existing severity precedence still applies, so
   no rule can weaken `DRAINING`, `FLATTENING`, or `HALTED`.
3. `PAUSED` blocks new exposure while cancellation, reconciliation, event
   ingestion, and separately authorized reduce-only handling remain available.
   `HALTED` blocks strategy submissions while preserving cancellation,
   reconciliation, and separately authenticated emergency handling. Neither
   action implies cancel, drain, flatten, or liquidation.
4. No policy observation, later healthy value, elapsed window, restart, or
   exact retry resumes an account. Only the existing proof-bound manual re-arm
   can lower operational state.
5. All rules are evaluated. Runtime action is the greatest required severity,
   while hypothetical rejection is an independent boolean. For example, a
   proposed concentration rejection and a current loss halt are both retained;
   the account halts and the batch receives no executable admission.

### 4. Session loss and drawdown

Let `o` be the regular-session open, `E_o` the exact positive canonical opening
equity, and `E_t` current canonical equity. The opening anchor includes every
admitted fact effective at or before `o`; later flow adjustment covers the
left-open interval `(o, t]`.

For admitted external cash contributions `C` and withdrawals `W`:

```text
adjusted_equity(t) =
    E_t - sum(contributions in (o, t]) + sum(withdrawals in (o, t])

session_loss(t) =
    max(0, (E_o - adjusted_equity(t)) / E_o)

session_high_water(t) =
    max(E_o, every complete adjusted_equity observation through t)

session_drawdown(t) =
    max(0, (session_high_water(t) - adjusted_equity(t))
           / session_high_water(t))
```

The account equity source is the canonical local execution ledger, FIFO account
projection, admitted corporate-action overlay, settlement projection, and
causal complete marks. Execution fees reduce equity exactly once. Admitted
dividend income and receivable are investment return; payment transfers
receivable to cash without recognizing income again. Contributions and
withdrawals are neutralized as external capital. A paper-account reset,
replacement account UUID, or unexplained broker balance change is an
identity/reconciliation failure, not a cash flow.

The session-opening equity and high-water observations form a durable,
gap-free account/session chain. Missing opening evidence or a nonpositive
denominator is not estimable; nonpositive current economic equity requires
`HALTED`.

| Rule | No breaker | `PAUSED` | `HALTED` |
|---|---:|---:|---:|
| Session loss | `<= 2.00%` | `> 2.00%` and `<= 3.00%` | `> 3.00%` |
| Session drawdown | `<= 2.50%` | `> 2.50%` and `<= 4.00%` | `> 4.00%` |

These are account-runtime rules. Once their assessment trips control, the
unchanged operational-state check rejects new exposure atomically.

### 5. Concentration and cash-account leverage

For each instrument, worst-case committed exposure is its current nonnegative
marked position value plus every unreleased remaining buy exposure from
approved-unsent, unknown-at-send, working, partially filled, and
pending-cancel orders. A sell does not reduce exposure before an authoritative
fill is applied, and a cancel request does not release capacity. A fill and its
released reservation may not both contribute the same economic quantity.

Concentration divides that instrument exposure by exact positive current
canonical equity. A proposed batch adds its conservative buy exposure without
netting proposed or pending sells:

| Concentration observation | Result |
|---|---|
| Proposed-only value `<= 35.00%` | No advanced-risk rejection |
| Proposed-only value `> 35.00%` | `REJECT` that exact batch only |
| Current/committed value `> 35.00%` and `<= 50.00%` | `PAUSED` |
| Current/committed value `> 50.00%` | `HALTED` |

Gross leverage is current gross long security exposure plus every unreleased
remaining buy exposure, divided by exact positive current canonical equity.
Absolute net security exposure must equal gross exposure in this long-only
scope. Proposed and runtime actions are:

| Leverage observation | Result |
|---|---|
| Proposed value `<= 1.00x` | No advanced-risk rejection |
| Proposed value `> 1.00x` | `REJECT` that exact batch only |
| Current/committed value `> 1.00x` and `<= 1.10x` | `PAUSED` |
| Current/committed value `> 1.10x` | `HALTED` |

The `1.10x` detector is not an allowance to borrow. Existing cash,
settlement, fee, reservation, and minimum-buffer rules remain stricter and run
unchanged. Negative positions, gross exposure unequal to absolute net
exposure, or nonpositive current equity are cash-scope/integrity violations and
require `HALTED` rather than evaluation against the tier.

Every positive ratio producer retains its exact numerator and denominator in
the authenticated source material. When division has more than the durable
`NUMERIC(28,10)` scale, the compared value is rounded outward with a ceiling to
ten decimal places. It is never rounded down to threshold equality. A positive
value smaller than one durable unit becomes `0.0000000001`; an unrepresentable
or nonpositive denominator produces typed incomplete evidence and the separate
integrity rule, never an infinity or maximum-value sentinel.

### 6. One-minute volatility

One complete observation requires 31 consecutive, watermark-complete
one-minute regular-session bars to produce 30 returns. All bars share one
admitted source/profile, calendar, security-master, and corporate-action
version. The window resets each session and never bridges an overnight gap.
For positive close prices:

```text
return(i) = close(i) / close(i - 1) - 1
volatility_shock = max(abs(return(i)) for the 30 returns)
```

A gap, correction not incorporated into the exact source version, invalid
price, mixed source, or fewer than 31 bars is incomplete data-health evidence,
not zero volatility. Only an instrument with proposed, current, or unreleased
buy exposure is relevant; an unrelated allow-listed symbol cannot trip the
account.

| Volatility observation | Result |
|---|---|
| Proposed-only shock `<= 1.50%` | No advanced-risk rejection |
| Proposed-only shock `> 1.50%` | `REJECT` that exact batch only |
| Current/committed shock `> 1.50%` and `<= 3.00%` | `PAUSED` |
| Current/committed shock `> 3.00%` | `HALTED` |

### 7. Spread and slippage

A spread source must be an admitted, entitled consolidated SIP quote lane with
valid condition handling. A single-venue IEX quote, completed bar, trade print,
or broker paper fill cannot be labeled NBBO. A quote requires finite positive
prices, `bid <= ask`, regular-session event and availability chronology, and
both event and receive age strictly less than five seconds at assessment.
Exactly five seconds is stale.

```text
mid = (bid + ask) / 2
full_spread_bps = 10_000 * (ask - bid) / mid
```

| Full-spread observation | Result |
|---|---|
| Proposed-only value `<= 20 bps` | No advanced-risk rejection |
| Proposed-only value `> 20 bps` | `REJECT` that exact batch only |
| Current/committed value `> 20 bps` and `<= 50 bps` | `PAUSED` |
| Current/committed value `> 50 bps` | `HALTED` |

The pre-trade modeled cost is the quoted half-spread in basis points plus a
separately versioned adverse latency/impact estimate that excludes spread.
This prevents double counting. Modeled cost `> 25 bps` rejects the exact
proposed batch; `25 bps` is within limit. A modeled hypothetical never trips
operational state.

Realized adverse slippage uses one exact durable dispatch/attempt time as
arrival unless a future authenticated provider arrival time is available. It
selects the latest qualifying nonfuture SIP quote under the same strict
five-second freshness rule. For side `s = +1` on a buy and `s = -1` on a sell:

```text
adverse_slippage_bps =
    10_000 * s * (fill_price - arrival_mid) / arrival_mid
```

Positive values are adverse and negative values are favorable. Execution fees
are excluded from this metric because account equity already includes them.
The rolling assessment selects the latest exactly 20 eligible provider
execution observations in `(observed_at - 30 minutes, observed_at]`; fewer than
20 is `INSUFFICIENT`. It computes the arrival-notional-weighted mean so broker
partial-fill splitting cannot change the economic weighting.

| Realized mean adverse slippage | Result |
|---|---|
| `<= 15 bps` | No breaker |
| `> 15 bps` and `<= 30 bps` | `PAUSED` |
| `> 30 bps` | `HALTED` |

Because Alpaca paper omits several live execution effects, these observations
qualify only paper/feed behavior and cannot satisfy a live-readiness gate.

### 8. Broker reject rate

The source set contains one canonical raw-first definitive outcome per locally
correlated new-entry submission attempt: broker accepted or broker business/
exchange rejected. It excludes local risk or validation rejection, cancel,
replace, reconciliation, emergency, manual, or foreign activity; unresolved
`UNKNOWN`, timeout, malformed, or `5xx` outcomes; and `429` or local
request-budget failures. Those retain their existing uncertainty, data-health,
or capacity semantics. A later canonical outcome may resolve uncertainty, but
an unresolved attempt is never counted as success.

Within the trailing ten-minute window:

- `PAUSED` when there are at least 10 definitive outcomes, at least 3 rejects,
  and `rejects / outcomes > 10%`;
- `HALTED` when there are at least 10 definitive outcomes, at least 5 rejects,
  and `rejects / outcomes > 25%`;
- independently, a suffix of 3 consecutive definitive business rejects inside
  the window requests `PAUSED`, and a suffix of 5 requests `HALTED`.

Exactly `10%` does not meet the pause rate, and exactly `25%` does not meet the
halt rate. A stable local attempt sequence orders the suffix. An unresolved
attempt in the sequence suspends rather than skips suffix evaluation; it does
not masquerade as an acceptance or join reject streaks across uncertainty.

### 9. Existing budgets remain authoritative

This policy does not loosen or reinterpret the existing complete-bar
15-second hard data age, five-second strategy deadline, 30-second approval TTL,
one-second clock-drift hard limit and 60-second healthy re-arm interval,
60-second unknown-submission budget, `160/180/200` broker request-capacity
protections, 120-second reconciliation budget, or critical-alert deadlines.
Their existing source and action contracts remain authoritative.

In particular, request-capacity rejection is not a broker business reject,
unknown submission is not a definitive reject-rate outcome, quote freshness is
a distinct five-second source requirement rather than a replacement for bar
freshness, and no advanced-risk recovery can bypass manual re-arm.

### 10. Source authority and current availability

| Rule family | Required authoritative source | Current source-audit status |
|---|---|---|
| Loss/drawdown | Durable session anchor/high-water chain over canonical local ledger, FIFO/corporate-action account projection, settlement, and complete causal marks | Point-in-time local economics exist; the durable session anchor/high-water producer is pending |
| Concentration/leverage | Same account evidence plus exact active reservation/unknown capacity under the current account fence | Local projections/reservations exist; authoritative broker application and account-wide runtime composition are pending |
| Volatility | Admitted watermark-complete SIP-trade-derived one-minute bar lane with pinned calendar, identity, and action versions | Fixture/replay contracts exist; no deployed admitted vendor producer is available |
| Spread/modeled slippage | Separately admitted, entitled consolidated SIP quote lane and versioned non-spread impact model | Unavailable; close-only data and single-venue quotes cannot satisfy it |
| Realized slippage | Canonically applied provider execution plus exact qualifying nonfuture SIP arrival quote | Unavailable; Phase 4 has no authoritative execution application and Alpaca paper cannot prove live quality |
| Reject rate | Canonically applied raw-first provider submission/order outcome tied to one local attempt | Raw-first local contracts exist; authoritative outcome application/taxonomy producer is pending |
| Broker request pressure | Durable account-local permit ledger bound to exact request purpose, fixed capacity policy, trusted issue/expiry time, and current fence | Locally implementable from Phase 4's durable permit facts; full deployed-path coverage is pending |
| Clock health | Authenticated trusted-time samples retaining source, host, absolute offset, monotonic/UTC correlation, sampling cadence, and the existing one-second/60-second recovery policy | Unavailable; no authenticated startup/in-session clock monitor exists |
| Data health | Admitted feed heartbeat plus complete-bar watermark/gap/arrival evidence under the pinned source, calendar, identity, and correction versions | Replay/fixture evidence exists; no deployed admitted feed-health producer exists |
| Account-wide UNKNOWN duration | Complete account-local projection of every unresolved canonical submission attempt, original dispatch/UNKNOWN times, fixed 60-second deadline, lookup schedule, current fence, and authoritative resolution application | Durable attempt and bounded lookup-schedule facts exist; complete deployed supervision and authoritative resolution are pending |
| Reconciliation duration | Authenticated barrier start, complete broker/local source membership, qualified two-view convergence, mismatch classification/disposition, and current fence under the fixed 120-second budget | Unavailable; current order/position comparisons are explicitly unqualified and nonconvergent |

There is no silent source fallback. Current close-only observations cannot
invent a quote, an IEX feed cannot invent an NBBO, broker account P&L cannot
replace the local ledger, and the current unqualified Phase 4 order/position
comparisons cannot establish canonical broker exposure, fills, rejects, or
clean reconciliation. Existing request-capacity, clock, complete-bar,
UNKNOWN-duration, and reconciliation values remain referenced policy inputs;
this ADR does not duplicate or loosen them. The fixed policy, evaluator,
additive schema, immutable assignment/evidence/assessment repository, and the
exposure-derived source seam are now implemented locally. The disabled-by-
default atomic control/risk/dispatch integration is also implemented and
covered by exact-retry, rollback, corruption, dispatch-gate, and migration
tests. That integration no longer accepts caller-built assessments: a
transactional producer must receive the exact current heads and economic
inputs, while the repository independently re-derives and compares the
snapshot/capacity/fence exposure observations and, for pretrade, the exact
Phase 2-derived proposed batch exposure. Replayed snapshot, capacity, batch,
fence, or assignment context fails before an assessment, trip, Phase 2
decision, or admission is written. Authoritative non-exposure runtime
producers, authenticated deployment assignment, and paper admission remain
pending.

### 11. Atomic assessment, trip, and admission

1. Keep the Phase 2 `phase2-atomic-batch-risk-v2` decision, reservation, and
   child-authorization semantic material unchanged. Add immutable Phase 5B
   policy, assignment, assessment, trip-binding, and admission-sidecar records
   rather than adding optional fields to historical facts.
2. Under the account serialization lock and one database transaction, verify
   the current fence, authenticated policy assignment, exact observation
   watermark, intent batch, account/risk snapshot, and complete active
   reservation/unknown capacity. The assessment binds those facts and the
   exact **pre-transition** operational-control head.
3. Evaluate every rule deterministically and append at most one greatest-
   severity `PAUSED` or `HALTED` trip. The trip binds the completed assessment
   digest in the same transaction. Binding the assessment to the pre-transition
   head and the trip to the assessment avoids a semantic digest cycle.
4. An additive admission sidecar binds the unchanged v2 decision and the exact
   final operational-control head after any trip. It can expose executable
   admission only when the assessment has no hypothetical rejection, the
   final head is the expected `RUNNING` head, the unchanged v2 decision is
   approved, and every shared policy/evidence/fence/snapshot/capacity binding
   agrees. A trip, stale head, missing sidecar, incomplete evidence, rejected
   v2 decision, or failed compare-and-set produces no executable child.
5. Historical exact retry returns the same assessment/trip/sidecar tuple.
   Reusing an account/idempotency identity with changed semantic input
   conflicts. A post-hoc assessment, separately committed trip, or sidecar
   attached after a legacy decision is never equivalent to the atomic path.
6. Dispatch revalidates the exact sidecar, final control head, fence, policy
   assignment, decision, reservation, and one-shot child before broker I/O.

### 12. Additive migration and quiesced cutover

Phase 5B persistence is additive. It does not backfill old v2 decisions with
fabricated assessments, assign the approved policy to an account, or make a
legacy authorization executable.

Before an account can receive its first runtime assignment, the environment
must be quiesced: no strategy invocation or dispatch may be active, every
pre-cutover approval must be expired or terminally disposed, every
reservation/unknown obligation must remain accounted for or be authoritatively
resolved, reconciliation must be clean, and operational state must remain
non-running until an authenticated cutover watermark is committed. After that
watermark, every new-exposure decision requires an exact Phase 5B admission
sidecar; mixed legacy/sidecar dispatch is forbidden. Empty development tables
may be downgraded, but nonempty policy assignment, assessment, trip, or
admission history refuses destructive downgrade.

## Consequences

Migrations 0026 and 0030, the fixed policy and deterministic evaluator,
immutable policy/assignment/evidence/assessment persistence, and the atomic
breaker/unchanged-Phase-2/admission-outcome composition are implemented
locally. Assignment commands bind the exact expected assignment head, so one
stale command cannot silently append after a concurrent winner, and each
persisted observation's source-set digest is recomputed from its exact retained
membership before any row is written. The outcome authenticates the complete
assessment, optional greatest-severity trip, unchanged v2 decision, admission
sidecar, final head, fence, lease, and expiry; retry is read-only and exact,
startup and final dispatch reauthenticate it, and a missing or corrupt outcome
denies dispatch. These are content-integrity boundaries, not proof that an
actor, account environment, or provider source is authoritative.

The exposure boundary is stronger than a caller-asserted context digest. Both
cutover and authorization run under the snapshot transaction and account SQL
lock. The repository independently reconstructs the exact exposure
watermarks, observations, and retained source membership and requires the
producer's full-policy result to contain them byte-for-byte. Runtime excludes
the proposed batch; pretrade includes the exact buy projection produced by the
unchanged Phase 2 reservation terms. The producer is mandatory and absent by
default.

The policy is not yet authenticated for any runtime account. Its required
session, SIP quote, canonical broker-application, and reconciliation producers
are not all available; no authenticated actor verifier or deployment cutover
command is wired; and no account is assigned or activated. Healthy
observations still have no automatic re-arm path, and the required deployed
end-to-end no-auto-resume and timed crash-fault drills remain pending. The
trader stays `not_ready`, paper and live startup fail closed, and the Phase 5
exit gate remains open.
