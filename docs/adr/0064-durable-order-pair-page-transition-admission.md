# ADR 0064: durable Alpaca order-pair page-transition admission

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4Z rejects process-local order-view composition that spans different
durable stores, but it deliberately leaves the same-store transition race
open. After Phase 4Q authenticates both Phase 4O sources and selects one exact
next page, an unscoped caller can still prepare either registered plan before
the selected provider request completes. The post-request reload detects that
mutation, but it cannot restore the consumed request permit or undo the broker
read.

Phase 4O originally retained a single-use preparation only in the mutable head
while a request was stalled and copied its fields into the completed page.
That representation proves no-resend behavior, but it does not provide one
stable immutable preparation row to which a durable page-transition
consumption can refer. Existing completed and stalled history must remain
readable through the change without inventing evidence.

Holding the account lock across credentials, request-capacity admission, and
provider I/O would replace the race with an unsafe long-lived transaction.
Phase 4AA therefore needs a short transactional admission seam before I/O and
an exact historical seam after restart. Phase 4AB will separately compose that
admission through the Phase 4Q/4O/4P runtime.

## Decision

1. Define Phase 4AA as the
   `phase4aa-durable-order-view-transition-admission-v1` application contract.
   Its fixed policy independently authenticates one ordered pair, one globally
   unique membership per plan, one claim for each exact next page, a gap-free
   same-role claim chain, exact preparation consumption, same-lease fencing,
   and no provider or reconciliation authority. It does not inherit the
   Phase 4Q policy digest.
2. Normalize every Phase 4O page preparation into the immutable
   `phase4_alpaca_paper_order_snapshot_preparations` projection. Its semantic
   digest is the primary identity, and the row retains the exact plan, page
   description and cursor, prefix capture and page count, predecessor page
   receipt and persisted-page digest, and historical preparation time.
3. Upgrade existing Phase 4O history without changing its meaning. Revision
   `0024_phase4_order_transition` projects one preparation from every completed
   page and from every sole `stalled` head, then verifies that the preparation
   count equals completed pages plus stalled heads. Exact plan and predecessor
   foreign keys, first/later-page shape checks, and unique page and
   preparation references reject gaps or substitutions. The loader
   reconstructs canonical preparation values from normalized columns rather
   than trusting mutable JSON or creating new evidence.
4. Treat the Phase 4O head's preparation fields as a pointer/cache. A
   preparation must be referenced by exactly one completed page or one stalled
   head, never both; completed pages retain the immutable fact after the head
   advances. Whole-store integrity rejects missing, multiply referenced, or
   orphaned preparation rows.
5. Permit revision `0024` to downgrade safely to `0023` by dropping only the
   derived preparation projection and its indexes. The original Phase 4O page
   and head source fields remain intact, so a later re-upgrade must reproduce
   the exact preparation history. This exception does not apply to the
   membership, claim, and consumption tables: they are non-derived admission
   facts, and downgrade fails while any such history exists.
6. Persist each admitted round as exactly two immutable member rows, one
   `earlier` and one `later`, for distinct Phase 4O plans on the same local
   account and traversal profile. Global uniqueness of snapshot, plan digest,
   and account/idempotency identities must prevent a plan from joining another
   round or changing roles.
7. Persist one immutable claim for each exact next page. The claim binds both
   memberships, selected role and plan, authenticated prefix and next-page
   description, preceding same-role claim when the prefix is nonempty, current
   account fence, and historical selection time. Continued claims must be
   gap-free and cannot change their predecessor chain.
8. Admit the first earlier-page claim only while both Phase 4O sources are
   absent, inserting both memberships and that claim atomically under the
   shared account lock. Resolve its race with direct Phase 4O preparation by
   lock order: if direct preparation wins, transition admission records
   nothing; if pair registration wins, public unscoped preparation of either
   member fails before credentials, request capacity, or transport. Every
   claim receives the exact prefix and authenticated source-head digest
   selected by Phase 4Q and rejects the admission if either changed before the
   account lock was acquired.
9. Admit a later-page claim only from the exact terminal earlier prefix and
   its authenticated source head. Selection must occur no earlier than the
   earlier terminal page's receive time plus two seconds and no earlier than
   that page's commit-fence validation. Every continued later claim retains
   that same earlier terminal source.
10. Consume a claim exactly once by atomically inserting the unchanged Phase
    4O preparation and a one-to-one transition-consumption row under the
    account lock. The preparation must name the claim's exact description,
    prefix, predecessor, and a preparation time no earlier than selection.
    The transaction ends before credentials, permit issuance, or provider I/O.
11. Require a second, nonregressing, pre-expiry same-lease fence validation
    after exact readback for every new claim and consumption. Exact claim
    retry returns historical evidence only after authenticating the current
    call fence. An unconsumed claim cannot transfer across lease renewal,
    revision, expiry, or takeover.
12. Preserve conservative crash behavior. A crash before consumption leaves
    no Phase 4O preparation and can resume only under the claim's exact current
    lease. A crash after atomic consumption leaves the existing Phase 4O
    stalled preparation and cannot resend. After a page commit, only the next
    exact page in the claim chain can be admitted.
13. Reconstruct every member, claim, preparation, consumption, Phase 4O
    source, predecessor, and fence during repository reads and whole-store
    readiness. Reject partial pairs, cross-round reuse, role swaps, gaps,
    substitutions, orphaned facts, consumed claims without their preparation,
    and registered preparations without an exact consumption.
14. Keep Phase 4AA non-authorizing. It performs no provider I/O and establishes
    no provider snapshot isolation or completeness, canonical order fact,
    convergence, application, reconciliation completion, readiness,
    submission, or trading authority.
15. Make Phase 4AB the explicit composition boundary. It must route every
    Phase 4Q source load and Phase 4P comparison source through exact
    membership/claim/consumption authentication, carry the selected claim's
    exact lease through the unchanged Phase 4O credential, budget, transport,
    commit, and reload path, and preserve the one-page-or-comparison bound.
    Phase 4AA alone does not make those runtime guarantees.

## Consequences

The application proof types, immutable preparation projection and exact
backfill, member/claim/consumption tables, SQL transition repository, public
unscoped-prepare exclusion, and transition-aware whole-store readiness are
implemented and verified. Existing completed and stalled Phase 4O histories
can move forward to the normalized representation and safely back to revision
`0023` only while the non-derived transition history remains empty.

The exact Q-selected prefix and source-head guard closes the stale-selection
race under the same account lock used by direct Phase 4O preparation. No
transaction spans credentials, request-capacity admission, or provider I/O.
Phase 4AB now composes these facts through the bounded Phase 4Q/4O/4P runtime;
Phase 4AA itself still grants no runtime or provider authority.

The resulting evidence remains a local single-use admission history, not
provider-qualified revision identity, snapshot completeness, reconciliation
convergence, lifecycle application, or trading authority.
