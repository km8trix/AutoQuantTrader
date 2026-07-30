# ADR 0059: durable authenticated Alpaca position-view comparisons

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4S can compare two bounded raw-first position arrays, and Phases 4T and
4U can execute and persist each array as a single-use authenticated capture.
Neither layer durably binds a comparison to the exact two authenticated source
receipts, however. A caller-supplied decoded view or difference set could
otherwise bypass source reconstruction, while a mutable or unsequenced result
would not remain independently auditable after restart.

Receive timestamps also require care. Phase 4S orders sources by their durable
raw-ingress sequence, but its signed receive-time separation can be negative
when a wall clock regresses. Persistence must retain that value rather than
invent a stronger monotonic-time claim.

## Decision

1. Define Phase 4V as the
   `phase4v-durable-authenticated-position-view-comparison-v1` application
   contract with the
   `phase4v-authenticated-position-view-comparison-persistence-v1` SQL
   boundary, and advance the additive schema head to
   `0022_phase4_position_view_cmp`.
2. Accept only an ordered pair of exact Phase 4T runtime plans. The
   `earlier` and `later` names are roles, not chronology; Phase 4S proves
   chronology only after both durable receipts have been loaded. Require the
   same local account and the same operator-pinned provider account UUID.
   Credential secret references, versions, binding IDs, and binding sequence
   numbers may rotate while that provider UUID remains unchanged.
3. Reload and fully reconstruct both exact Phase 4U receipts. Recompute the
   Phase 4S view digests, added/removed/changed asset IDs, signed receive-time
   separation, and disposition internally. Do not accept caller-supplied
   positions, views, differences, or a disposition.
4. Store one immutable comparison row containing the application-plan,
   evidence, comparison, both exact source receipt/plan/capture/raw-ingress
   identities and digests, source commit instants, provider account UUID,
   commit fence, and canonical receipt.
5. Add ordered composite foreign keys from each comparison role to an exact
   Phase 4U receipt position. Enforce distinct source identities and strictly
   increasing raw-ingress sequence. Deliberately add no receive-time ordering
   constraint; a negative signed separation is valid historical evidence and
   remains a waiting disposition.
6. Serialize appends with the shared account lock and retain a gap-free
   account-local sequence, predecessor digest, and terminal head. A stable
   source-pair identity permits exactly one result under the fixed policy.
7. For every append, reconstruct both sources and the complete existing
   comparison history inside the same transaction. Independently revalidate
   the current call's account fence. A new receipt records that transaction
   fence and must not predate either source commit.
8. Treat an exact retry as idempotent. It must still reauthenticate both
   sources, the account-local history, and the current call fence, but it
   returns the original historical receipt without rewriting its fence,
   sequence, predecessor, or recorded time.
9. Make receipt loading, account history, and whole-store readiness
   verification reconstruct the application plan, both Phase 4U sources,
   Phase 4S comparison, historical fence, receipt chain, and head. Source
   substitution, fork, rollback, missing rows, orphans, provider-account
   mismatch, and canonical-payload drift fail closed.
10. Refuse downgrade while comparison rows or heads remain. Schema revision
    alone is insufficient for readiness; full comparison integrity
    verification is mandatory.
11. Keep the result historical and non-authorizing. It performs no provider
    I/O and establishes neither provider snapshot isolation/completeness,
    monotonic timing, canonical positions, application, convergence,
    reconciliation completion, readiness, UNKNOWN resolution, submission, nor
    trading authority.

## Consequences

Two exact authenticated position captures can now produce one restart-stable,
source-authenticated durable comparison without promoting equality to
convergence. Exact retries are safe across a fence or credential-version
rotation, while a local account remap to another provider UUID is rejected.

Bounded pair supervision, combined account/order/position reconciliation,
activity and fill views, stream overlap, provider-qualified event identities,
authoritative application, convergence, deployed composition, and the Phase 4
exit gate remain open.
