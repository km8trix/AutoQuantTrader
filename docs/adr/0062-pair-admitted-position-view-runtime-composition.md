# ADR 0062: pair-admitted Alpaca position-view runtime composition

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4X reserves an ordered position pair and can atomically consume one role
claim with the unchanged Phase 4U preparation. Phase 4W still accepts a generic
capture workflow, however, and Phase 4T normally calls the public Phase 4U
`prepare` operation. Merely checking Phase 4X before calling Phase 4W would
leave a check-to-use race, while holding the account-lock transaction across
credentials, permit allocation, and provider I/O would be unsafe.

An account fence identifies an owner, lease ID, and fencing generation, but it
does not identify a particular renewable lease revision. Consequently, passing
only the same `AccountFence` from Phase 4X into Phase 4T could allow the claim
to be consumed under one lease digest and the provider request to begin after a
renewal. A restart also must not allow legacy or directly prepared Phase 4U
receipts to bypass pair admission on the comparison-only path.

## Decision

1. Define Phase 4Y as the
   `phase4y-pair-admitted-position-view-runtime-v1` application contract. It
   adds no schema, scheduler, worker, resolver, or provider endpoint.
2. Accept one exact Phase 4X transition plan and require the transition,
   Phase 4U, Phase 4T workflow, Phase 4V comparison, and account-coordinator
   ports to expose the same opaque process-local durable-store identity. Reject
   a mismatch before loading state, reading the clock, claiming a role, or
   performing an effect.
3. Wrap every Phase 4W `load_state` and every Phase 4V source `load`. An
   `ABSENT` member may have no claim or one exact unconsumed historical claim.
   `STALLED` and `COMPLETE` members require the exact role claim and its exact
   consumption bound to that Phase 4U preparation. An absent member with a
   consumption, a direct/unscoped non-absent source, or any substituted pair,
   role, preparation, or prior-earlier receipt fails closed before effects.
4. Keep Phase 4W as the bounded inner selector. One Phase 4Y invocation can
   therefore claim and execute at most one selected capture, wait without I/O,
   or append one Phase 4V comparison. It never loops, sleeps, or executes both
   captures.
5. Claim the selected Phase 4X role before invoking Phase 4T. This ordering
   ensures Phase 4T's trusted `prepared_at` is sampled after the immutable
   claim's `selected_at`. Exact claim readback must bind the pair, role, plan,
   and supplied account fence.
6. Supply Phase 4T a claim-bound snapshot-runtime adapter. Its sole `prepare`
   calls Phase 4X `prepare_claimed`, which atomically inserts the unchanged
   Phase 4U plan and consumption under the account lock. It reloads both exact
   records before returning the canonical Phase 4U preparation. A second call,
   another plan, or an already consumed claim fails before credentials,
   request capacity, or transport.
7. Close the claim/consumption transaction before Phase 4T continues. Delegate
   Phase 4T's unchanged `record` and `load` calls to Phase 4U only after exact
   consumption. A crash after consumption retains the existing Phase 4U
   `STALLED` meaning and can never resend.
8. Supply Phase 4T a restricted coordinator adapter. Every revalidation must
   match the consumption's exact fence, coordinator policy digest, lease
   digest, and lease expiry, must not predate consumption, and must remain
   pre-expiry. Renewal, takeover, or expiry after consumption therefore fails
   no later than the next Phase 4T fence check; a change after the pre-request
   check may leave one raw-first response but cannot commit Phase 4U.
9. Defensively require Phase 4T's pre-, post-, final-, and Phase 4U commit-fence
   receipts to carry that same exact consumption lease and nonregressing
   chronology. Apply the same check when authenticating restarted `COMPLETE`
   sources, so another-lease receipt cannot reach Phase 4V.
10. After a selected Phase 4T call, require its returned, recorded, and loaded
    receipt to be identical and to bind the consumed preparation. Phase 4W
    then reloads both sources through the pair-authenticating wrapper and
    accepts only the expected selected Phase 4U transition with the peer
    unchanged.
11. Return a proof-constructed Phase 4Y result that retains the unchanged
    Phase 4W result and the exact required Phase 4X claim/consumption history.
    The earlier history is required for every returned stage; later history is
    required once the later source is non-absent. A later claim must name the
    exact earlier receipt in the Phase 4W result.
12. Keep all outputs historical and non-authorizing. Phase 4Y does not
    establish provider snapshot isolation or completeness, provider revision
    identity, canonical positions, convergence, application, reconciliation
    completion, readiness, submission, or trading authority.

## Consequences

Phase 4X is now composed through the unchanged Phase 4T evidence path and the
bounded Phase 4W selector. A registered position pair has a closed pre-effect
race against public Phase 4U preparation, exact lease continuity through the
provider-read path, restart-authenticated comparison sources, and no database
transaction across network I/O. Concurrent callers may both reach role-claim
lookup, but only one can consume the single-use preparation and reach the
provider request.

This remains a local composition contract, not a deployed reconciliation
worker. There is no automatic claim recovery or lease transfer, order-pair
equivalent, combined account/order/position barrier, activity or fill
coverage, stream overlap, provider-qualified revision/execution identities,
decode quarantine, authoritative application, convergence, or Phase 4
readiness.
