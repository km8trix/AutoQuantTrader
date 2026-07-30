# ADR 0043: offline Alpaca dispatch-preflight evidence binder

- Status: Accepted
- Date: 2026-07-27

## Context

Phases 4A through 4E now provide an immutable Alpaca paper request
description, strict client-order/account/asset observations, raw-first ingress
receipts, and durable request-budget permits. Phase 2 already provides
proof-constructed submission attempts, single-use batch-risk authorizations,
capacity reservations, complete-parent `UNKNOWN` barriers, and stable account
fences. Those contracts expose the identities and semantic digests needed to
detect inconsistent dispatch evidence.

They do not yet form a send capability. In particular, the account and asset
observations are documentation-derived or otherwise unqualified evidence, the
budget permit does not authorize transport, and no authenticated credential,
provider-account binding, current security master, quote/collar check,
reconciliation barrier, or paper-startup authority exists. Treating a
caller-supplied readiness boolean as a substitute would erase those distinctions
and allow locally consistent but unauthenticated evidence to appear executable.

The repository nevertheless needs one deterministic place to cross-bind the
existing evidence and enumerate why a candidate remains blocked. That boundary
must stay pure and useful for adversarial tests without weakening the final SQL
and coordinator checks that precede a real broker effect.

## Decision

1. Define Phase 4F as a pure, offline Alpaca paper dispatch-preflight evidence
   binder. It accepts exact immutable values, revalidates their internal
   contracts, cross-binds their identities and digests, and produces a
   deterministic non-authorizing assessment. It performs no filesystem,
   database, secret-store, clock, HTTP, WebSocket, or other I/O.
2. Bind one exact reducer-produced `CanonicalSubmissionAttempt`; only a current
   `PENDING` state avoids an attempt-status blocker. Also require the
   canonically ordered, complete supplied snapshot of attempts for the same
   parent risk decision and recompute the existing parent submission barrier.
   Each logical order's attempt-number slots must be unique and contiguous
   from one. A reused identity or logical slot, omitted predecessor, wrong
   parent, non-canonical order, or attempt projection that does not reduce from
   its immutable events is a hard conflict. A valid non-`PENDING` state or
   unresolved parent `UNKNOWN` is instead an expected closed blocker. The
   binder does not claim that a caller-supplied tuple is a durable database
   snapshot; final SQL revalidation remains mandatory.
3. Bind the attempt preparation to one exact
   `AlpacaPaperSubmissionDescription`. The account, intent, deterministic
   logical-order and client-order IDs, adapter and operation, canonical
   `BrokerSubmissionRequest`, request digest, capability digest, instrument,
   symbol, side, whole-share quantity, and exact provider JSON body must agree.
   A description or request mismatch is a hard evidence conflict rather than a
   status blocker.
4. Bind the approved child `BatchRiskAuthorization`, its parent
   `BatchRiskDecision` and `BatchRiskReservation`, and the exact
   `BatchRiskSession` named by the authorization's session digest. Bind a
   supplied active-capacity projection to the same
   reservation and child authorization, including reservation currency, child
   intent/instrument/side, original reserved terms, state, remaining cash, buy
   exposure, and sell quantity. Immutable identity or original-term drift is a
   hard conflict; only valid state and remaining-capacity reductions become
   closed status findings. The projection must not be used as proof of durable
   completeness; the SQL submission repository remains authoritative for
   current reservation, release, `UNKNOWN`, and correction state.
5. For a sell candidate, require the risk authorization and current capacity
   projection to retain the exact whole-share sell quantity for the intent.
   Asset `shortable`, `easy_to_borrow`, `marginable`, or `fractionable` fields
   never prove reduce-only behavior and never authorize short or fractional
   exposure. A later current position/reconciliation check is still required
   immediately before dispatch.
6. Bind one fresh `AccountFenceReceipt` to the preparation's stable
   `AccountFence` and lease policy. The receipt's `validated_at` is the only
   assessment instant; callers cannot provide an independent time or freshness
   boolean. Risk approval, intent, session, observations, and permit are
   compared against that instant with half-open expiry semantics. The binder
   cannot prove that this receipt remains current after assessment, so the
   coordinator must revalidate the same stable fence again at the real effect
   boundary.
7. Bind exact raw-first `PersistedAlpacaAccountObservation` and
   `PersistedAlpacaAssetObservation` values. Their receipt, description,
   account, provider, adapter, paper environment, operation, status, request
   ID, receipt time, exact body, body digest, normalized observation digest,
   and, for the asset, fixed candidate instrument/symbol must agree with the
   attempt and request description. A locally usable-candidate outcome can
   avoid a local status blocker, but it cannot establish authenticated provider
   provenance, observation freshness, a provider-account binding, or a durable
   security identity.
8. Bind the exact fixed `ALPACA_PAPER_REQUEST_BUDGET_POLICY`, one
   `BrokerRequestDemand` mapped to purpose `submission` and operation
   `submit_order`, and its exact `BrokerRequestPermit`. The demand's correlation
   digest is a versioned canonical hash derived from both the
   `SubmissionAttemptPreparation.semantic_sha256` and
   `AlpacaPaperSubmissionDescription.semantic_sha256`; it is not a free-form
   caller value. The permit must bind that demand and policy and be fresh at the
   fence receipt's assessment instant.
9. The caller supplies the demand's bounded admission idempotency key. Phase 4F
   validates its existing safe-text and length contract but neither invents nor
   changes it. A stable policy for replacement orders, superseding attempts,
   and future transport retries remains unresolved. Consequently, the binder
   cannot claim that demand identity is the final end-to-end replacement or
   resubmission policy.
10. Separate malformed or contradictory evidence from expected fail-closed
    conditions. Wrong exact types, cross-account values, altered semantic
    digests, a request/intent mismatch, a changed stable fence, a wrong session
    digest, an active-capacity identity mismatch, or a permit bound to another
    demand or policy are hard conflicts and reject construction. Expected
    temporal and provider-status conditions produce a unique, canonically
    ordered closed blocker tuple instead: non-`PENDING` state, unresolved
    parent `UNKNOWN`, expired risk/intent/permit, closed session,
    inactive or blocked account, incomplete account evidence, ineligible or
    inconclusive asset, released/frozen/insufficient capacity, and an unproven
    reduce-only sell.
11. Separately retain the frozen unresolved runtime-gate tuple for
    prerequisites that the current repository cannot prove: credential
    resolution; authenticated and current provider-account binding;
    authenticated and current security identity/tradability; a current quote
    and collar; durable budget freshness at the effect boundary; current
    reservation and control-state revalidation; converged reconciliation;
    paper-startup readiness; final coordinator-fence revalidation; and the
    durable `PENDING -> IN_FLIGHT` transition. No combination of Phase 4F's
    offline inputs can make these gates ready.
12. Content-authenticate the assessment with a versioned semantic digest over
    the attempt/preparation, complete parent snapshot, request description,
    risk authorization/reservation/session, active-capacity projection, fence
    receipt, account and asset receipts/observations, budget policy/demand/
    permit, assessment instant, and ordered blocker tuple. The assessment
    contains no credential values or authentication headers.
13. Keep `credential_resolution_ready`, `authenticated_account_ready`,
    `account_observation_current`, `authenticated_security_ready`,
    `asset_observation_current`, `security_mapping_ready`,
    `asset_tradability_validation_ready`, `reduce_only_validation_ready`,
    `exchange_calendar_binding_ready`, `session_validation_ready`,
    `quote_collar_ready`, `current_reservation_ready`,
    `reconciliation_ready`, `paper_startup_ready`,
    `request_budget_enforced`, `transport_submission_ready`,
    `mark_in_flight_ready`, `coordinator_dispatch_ready`,
    `dispatch_preflight_ready`, and `trading_effect_authorized` false. The
    assessment cannot be converted into headers, call a transport, persist a
    fact, normalize broker data, apply a lifecycle transition, mark a
    submission in flight, or authorize any broker effect.
14. Add no table or migration for this slice. The real
    `SqlSubmissionAttemptRepository.mark_in_flight` path remains the final
    transactional revalidation of the current fence, reservation capacity,
    complete-parent `UNKNOWN` barrier, correction freeze, risk and intent
    expiry immediately before any future transport. A later dispatch
    orchestrator must also reauthenticate the durable budget permit and all
    authenticated runtime evidence under the current fence before it may invoke
    the broker.

## Consequences

Phase 4F can expose one reproducible explanation of which existing evidence
agrees and which dispatch prerequisites remain absent. Cross-account,
cross-intent, altered-request, stale-time, status, and capacity cases can be
tested without credentials, network access, or a database, while synthetic
account and asset fixtures remain visibly non-authorizing.

This slice deliberately stops before runtime readiness. It does not resolve a
credential, authenticate an Alpaca response, bind the local account alias to a
provider UUID, publish a security master, acquire a current quote, establish
reconciliation or control state, consume a budget permit at transport, persist
a preflight receipt, transition an attempt, or send an order. Those later
contracts must replace the permanent blockers with proof-constructed,
freshness-bounded evidence and define atomic dispatch sequencing before paper
startup can be enabled. Phase 4 and its exit gate remain open.
