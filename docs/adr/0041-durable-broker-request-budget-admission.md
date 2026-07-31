# ADR 0041: durable broker request budget admission

- Status: Accepted
- Date: 2026-07-26

## Context

ADR 0038 records Alpaca's currently documented ceiling of 200 Trading API
requests per minute per account, but Phases 4A through 4C neither allocate nor
enforce that capacity. A process-local limiter would be unsafe: two trader
processes, a restart, or a crash between admission and a broker call could
consume more capacity than either process can observe.

Broker capacity also has safety precedence. New-exposure submissions must not
exhaust the capacity needed to investigate an `UNKNOWN` submission, cancel an
order, or run reconciliation. Conversely, a returned or expired local permit
cannot safely be refunded because the database cannot prove that an external
request did not leave the process.

The provider documentation does not qualify an exact wall-clock reset boundary.
A local fixed-minute bucket could therefore permit a burst across its boundary
that exceeds a provider rolling window.

## Decision

1. Define Phase 4D as a provider-neutral, durable request-admission slice.
   A versioned `BrokerRequestBudgetPolicy` records the provider/environment,
   rolling-window duration, total ceiling, progressively smaller recovery and
   submission ceilings, and short permit lifetime. A semantic digest binds
   every field.
2. Use a closed request-purpose vocabulary:
   `submission`, `unknown_lookup`, `cancel`, and `reconciliation`.
   Submission is admitted only below the submission ceiling; UNKNOWN lookup is
   admitted below the recovery ceiling; cancellation and reconciliation may
   use the total ceiling. Every admitted request counts against all higher
   ceilings because all purposes share one provider account budget.
3. Select the initial Alpaca paper policy as a 60-second local rolling window,
   total ceiling 200, submission ceiling 160, recovery ceiling 180, and
   three-second permit lifetime. The final 20 permits are therefore available
   only to cancellation/reconciliation, and the preceding 20 are available to
   UNKNOWN lookup plus those critical purposes. These smaller ceilings and
   lifetime are local operational policy, not provider facts.
4. Retain each permit in local accounting through
   `permit.expires_at + window_duration`, because a future request may be sent
   at any fresh instant before permit expiry. The selected three-second
   lifetime therefore creates a conservative 63-second accounting horizon for
   a 60-second provider window. Boundary equality remains active; capacity
   returns only after time moves strictly beyond it. This does not claim to
   reproduce an undocumented provider algorithm. It prevents both a
   fixed-boundary burst and a near-expiry dispatch from aging out early. The SQL
   allocator samples its injected trusted UTC clock only after acquiring the
   account lock; callers cannot supply an issue time that artificially ages
   prior permits.
5. Require each demand to bind an account, stable idempotency key, operation,
   purpose, correlation digest, and UTC request time. Its selected policy binds
   the provider and environment. An exact account/key retry returns the
   original permit without debiting the window again. Changed immutable demand
   or policy content under that identity is a conflict. That lookup-oriented
   replay API is not authority to resend an external request: a network path
   must use new-only issuance, which rejects an already admitted demand before
   transport unless a separate durable effect record proves that it can
   short-circuit to the prior outcome.
6. Serialize allocation under the existing database account-transition lock.
   New permits receive a contiguous account-local budget sequence, bind their
   predecessor sequence and digest, and atomically advance a terminal head.
   Composite relational keys require every later permit to reference exactly
   sequence `n - 1`, and require the head's sequence/digest pair to reference
   the exact terminal row. Point reads, history reads, and startup verification
   authenticate the immutable chain and head.
7. Treat grant as conservative capacity consumption even if the future caller
   never sends a request. There is no release, refund, or mutable consumed flag.
   This deliberately turns a crash after allocation into temporary lost
   capacity rather than possible over-admission.
8. Reject a new policy while the terminal permit under another policy remains
   inside its expiry-plus-window accounting horizon. A policy may change only
   after that prior horizon drains, preventing a policy digest change from
   resetting capacity. Reject regressing issue times so durable UTC ordering
   cannot be rewound to evade accounting.
9. A fresh permit proves only that local request capacity was admitted. It
   carries no credential, headers, body, network client, account lease, risk
   approval, or transport authority. Expiry never refunds its capacity.
   Future transport must obtain the permit through new-only issuance, recheck
   it through the allocator's trusted clock, and enforce every
   purpose-specific fence and authorization. A crash after new-only issuance
   remains a conservative lost slot; retry requires a new demand identity and
   another debit unless a later durable effect protocol can prove reuse safe.
10. Keep Alpaca's `request_budget_enforced` and all other runtime-readiness flags
   false. No network-capable path is yet forced through this boundary, so the
   repository cannot truthfully claim end-to-end enforcement.

## Consequences

Concurrent processes and restarts now share durable admission evidence rather
than independent memory counters. Lower-priority traffic cannot consume the
protected tail of the configured account budget, exact retries do not double
debit it, and a crash cannot create extra capacity by refunding an ambiguous
permit.

The checked-in ceiling is a local safety policy, not evidence of authenticated
provider behavior. Its provider limit remains the value reviewed in ADR 0038;
the smaller submission/recovery ceilings and permit lifetime are versioned
operational configuration and require explicit review to loosen.

Phase 4D does not resolve credentials, perform HTTP or WebSocket I/O, schedule
delayed lookup, paginate snapshots, classify normalized broker facts, resolve
`UNKNOWN`, run reconciliation, dispatch an order, or enable paper/live startup.
Phase 4 and its exit gate remain open.
