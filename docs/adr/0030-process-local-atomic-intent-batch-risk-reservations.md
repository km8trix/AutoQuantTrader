# ADR 0030: process-local atomic intent-batch risk reservations

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0023 creates one canonical multi-instrument `OrderIntentBatch`, but the
Phase 0 risk repository evaluates and reserves one intent at a time. Sequential
approval can partially authorize a rebalance, spend the same capacity twice, or
allow parallel sells to reserve more shares than the account owns. ADR 0029's
simulated broker correctly requires a current exact-payload one-shot approval,
but that requirement alone does not prove that every member was evaluated
against one account, price, session, and control snapshot.

The recently added accounting boundaries expose different economic views that
must not be conflated. Post-corporate-action account positions establish the
shares available to sell; settlement `available_cash` excludes unsettled sale
receivables and open trade payables; causal portfolio prices establish the
reference facts used by the intents. Pending orders also remain exposure even
when they have not yet reached, or have not been resolved by, a broker.

This slice must establish the batch decision and reservation semantics before
coordinator fencing and durable multi-order dispatch are added. It remains a
pure, process-local simulation boundary and cannot claim crash safety or
paper/live trading authority.

## Decision

1. Add an independent Phase 2 batch-risk contract without changing the Phase 0
   `RiskDecision`, `RiskLimits`, repositories, walking thread, or compatibility
   broker. The new authority owns the versioned policy, one account-scoped
   snapshot provider, and evaluation and consumption clocks. The provider owns
   the current account/session/control evidence, its transition transaction
   seam, and the shared process-local reservation store; callers cannot
   substitute capacity, policy, control state, store, or time per request.
2. Evaluate one exact `OrderIntentBatch` together with its exact
   `TargetPortfolio` and causal `PortfolioSnapshot`. Re-run the canonical
   target-to-intent conversion and require the supplied batch to equal the exact
   derived position delta; matching IDs or isolated member payloads are not
   sufficient. Then reprove the enclosing target, trigger, and snapshot
   bindings and every member's instrument, symbol, source event identity and
   digest, reference price, event/availability time, creation time, and expiry.
   Missing, stale, future, substituted, or inconsistent evidence fails closed.
3. Construct the trusted capacity snapshot through an explicit projection
   attestation seam. The account and settlement states are reducer-produced,
   publicly non-instantiable proofs whose retained aggregates are independently
   re-derived. They must share one stable account identity, uppercase currency,
   exact trade-date ledger, and execution-ledger digest; the account and
   portfolio must share one `as_of`, settlement cannot come from the future, the
   exact post-corporate-action position tuple must match the portfolio, and
   every open position's account mark must match its causal portfolio event
   identity, value, effective time, and recorded time. The attestation derives
   the account identity, positions, current gross exposure from canonical
   position market values, and conservative settlement `available_cash` from
   canonical cash and payable balances, plus the projection and ledger digests,
   rather than trusting loose copies. The resulting risk snapshot is also
   publicly non-instantiable, retains both exact projections, and binds those
   facts to one version, currency, and session. Snapshot validation revalidates
   the embedded proofs and independently re-attests every flattened identity,
   capacity, digest, position, currency, and time field. Provider admission and
   every repository use, as well as direct evaluation, invoke that validation,
   so low-level object copying cannot inject cash or exposure. Reusing a version
   with different semantics is a fact conflict. Evaluation cannot precede the
   intent, portfolio, accounting, settlement, session, or operational-state
   evidence it consumes.
4. Make session and control state explicit evidence. Only the configured
   regular-hours session, including a declared shortened half-day, is eligible.
   Intent creation, reference events, evaluation, approval expiry, and
   consumption must fit the session. The normal strategy path rejects while
   paused or halted; cancellation and separately authorized reduce-only recovery
   remain outside this contract.
5. Apply one fixed, versioned, deterministic rule set to the complete batch:
   duplicate/evidence consistency, operational state, instrument allow-list,
   session, reference and snapshot freshness, intent expiry, per-order quantity
   and notional, aggregate batch notional, available cash and minimum buffer,
   long-only shares, per-instrument and account gross exposure, and daily/open
   order counts including active pending reservations. Rules may approve or
   reject; this boundary never silently resizes or rewrites an intent.
6. Reserve conservatively without intra-batch or pending-order netting. Buy cash
   uses the reference price plus the policy's explicit adverse per-share buffer,
   and every member includes explicit fixed and per-share fee reserves. Sells
   reserve fees and shares but never contribute proceeds to buying capacity.
   Pending sells do not reduce gross-exposure capacity, pending buys increase it,
   and buys never offset shares reserved by a sell. Arithmetic uses the existing
   context-independent exact decimal and persisted-value bounds.
7. A nonempty batch is approved or rejected as a unit. Approval creates one
   immutable parent decision and reservation plus one sorted, exact-payload,
   one-shot child authorization for each intent. A child binds its parent,
   reservation, policy, account, exact session digest, operational state,
   portfolio snapshot, uppercase currency, and intent payload. Parent decision,
   reservation, and every child agree on that currency. A rejected batch creates
   no reservation or executable child. A canonical empty batch produces
   explicit no-action evidence and no execution capability.
8. Count every approved reservation as active after issuance and consumption.
   This includes approved-unsent, ambiguously submitted, working, partially
   filled, and pending-cancel exposure. This process-local slice deliberately
   retains capacity rather than guessing that an expiry, submission failure,
   cancellation request, or local terminal view released an economic obligation.
9. Exact retries are idempotent. Reauthorizing the same batch with identical
   batch, price, account, session, control, and policy evidence returns the same
   decision without reserving twice. Reusing a batch, intent, snapshot, decision,
   reservation, or child identity with different semantics raises a fact
   conflict and changes no state. Any member rule failure rejects the whole batch
   and cannot leave a partial hold.
10. A child can be consumed exactly once and only for its bound intent while its
    parent, payload, intent, price, control, currency, and session windows remain
    current. It exposes the reserved maximum execution price and cash
    requirement and binds the exact risk-session digest. Before consumption, the
    simulator validates only current immutable context: both caps are exact and
    internally sufficient, its pinned session reproduces the authorization's
    session digest, and its model currency equals the authorization currency. A
    malformed cap or mismatched session/currency fails without consumption or an
    order fact.

    After those static checks, the repository consumes the child from current
    evidence and the simulator records acceptance. The returned exact
    consumption/submission time plus configured latency determines activation.
    The simulator then considers only the first relevant sealed source slice
    strictly later than that activation; a later unreachable tape suffix cannot
    change the selected source, outcome, or broker/order facts, although the
    result still binds its full observation tape and horizon. If no source is
    eligible, the accepted order remains working. If the first slice is
    incomplete, or its complete exact instrument event cannot produce valid
    execution arithmetic, the simulator emits no execution and returns an
    explicitly accepted, working, deferred-source-blocked result. Exact evidence
    binds the reason, working order, caps, source slice and optional event,
    model, session, and causal times. If valid computed terms instead breach the
    buy-price, buy-notional-plus-fee, or sell-fee cap, the simulator returns an
    explicitly accepted, working, cap-blocked result with exact source and term
    evidence. In every blocked case the child remains consumed and the complete
    parent hold remains active. A later source cannot retroactively suppress the
    earlier authorization consumption or acceptance. Result validation
    re-derives first-source selection and proves the recorded block rather than
    trusting an outcome label.

    The repository exposes the existing narrow authorization consumer shape, so
    the ADR 0029 broker can consume a child before creating a submission. A
    missing, rejected, expired, mismatched, or reused child produces no broker
    fact. If one external member later becomes ambiguous, all related holds must
    remain; the system may not roll back a possible broker effect or release the
    unsubmitted remainder by assumption.
11. A process-local account registry maps each active account identity to one
    snapshot state, shared reservation store, and reentrant transition lock.
    Providers opened with the same account and exact initial snapshot share that
    state automatically; conflicting initial evidence fails closed instead of
    creating a second capacity universe. Every repository for the one exact
    authority shares the same decisions, reservations, authorizations,
    consumption markers, and store lock, while binding a distinct authority to
    that account state is rejected. Authorization and consumption run through
    the provider transaction and then the shared store lock, so a snapshot
    transition cannot interleave with capacity evaluation, reservation
    publication, or consumption validation. This proves serialization only
    inside one runtime and is not a substitute for a database transaction or an
    account-coordinator fence.

## Consequences

The complete rebalance now crosses one deterministic risk boundary: no member
can receive an executable child authorization unless the supplied target
re-derives the exact batch, the account/settlement projection attestation passes,
every member passes against the same session- and currency-bound evidence, and
the complete cash, share, notional, and exposure hold is installed. Parallel
repositories or providers sharing one active account cannot reserve the same
cash or shares, exact retry is safe, pending exposure remains conservative, and the
existing simulated broker can exercise approved buys and sells through its
unchanged per-intent submission port.

Process death still loses the in-memory decisions, consumption markers, and
holds. Durable SQL batch decisions/reservations, atomic persistence with logical
orders and submission attempts, lease/fencing rechecks, lifecycle-driven partial
release, expiry sweeping, unknown-submission recovery, reconciliation, and
crash-boundary fault tests are deferred to the coordinator/durable execution
slice. Quote collars and dispatch-time quote freshness, separately authorized
reduce-only/flatten flows, margin or sale-proceeds funding, multi-strategy
netting, concentration/leverage/loss rules, paper/live adapters, and trading
authority also remain gated. A later simulated cap breach is represented as a
post-acceptance execution block and never as permission to erase prior causal
facts or release reserved capacity.
