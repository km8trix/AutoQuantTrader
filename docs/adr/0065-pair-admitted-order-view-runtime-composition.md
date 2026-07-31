# ADR 0065: pair-admitted Alpaca order-view runtime composition

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4AA reserves an ordered pair of paginated order captures and can
atomically consume one exact next-page claim with the unchanged Phase 4O
preparation. Phase 4Q still accepts generic state, page-workflow, and Phase 4P
comparison ports, however, while the unchanged Phase 4O runtime normally calls
the public unscoped `prepare_next` operation. Merely claiming a page before
calling Phase 4Q would not prove that the claim names the prefix and source
head selected by that exact supervisor invocation.

A paginated capture may also span several account-lease revisions. Requiring
one lease for the whole capture would reject valid historical page chains, but
checking only the newest lease would allow an earlier page, preparation, or
receipt to bypass its own admission. Restarted comparison-only calls likewise
must not accept direct Phase 4O history that lacks the exact claim and
consumption for every page.

Holding the account lock across credentials, request-capacity admission, and
provider I/O remains unsafe. Phase 4AB therefore needs narrow adapters that
carry one selected claim through one unchanged Phase 4O page execution while
authenticating the full existing chain page by page.

## Decision

1. Define Phase 4AB as the
   `phase4ab-pair-admitted-order-view-runtime-v1` application contract. It adds
   no schema, migration, provider endpoint, retry, scheduler, worker, or secret
   resolver.
2. Accept one exact Phase 4AA transition plan and current account fence. Require
   the transition repository, Phase 4O snapshot runtime, claimed page workflow,
   account coordinator, and Phase 4P comparison repository to expose the same
   exact positive process-local durable-store identity. Reject a missing,
   invalid, exceptional, or unequal identity before loading either source,
   consulting the clock, claiming a page, or performing an effect.
3. Wrap Phase 4Q's state and prefix loader with a pair-authenticating loader.
   For every committed page, require the exact role claim, one-to-one
   consumption, unchanged Phase 4O preparation, and exact page receipt. The
   claim chain must be ordered, gap-free, and bound to the supplied transition
   and role. Every later-page claim must additionally bind the exact
   authenticated terminal earlier prefix and source-head digest. A direct or
   substituted non-absent source fails closed.
4. Authenticate each page against its own claim and consumption lease. Claims
   in one page chain may belong to different successive leases, but each
   page's preparation, pre/post checks, commit receipt, and durable
   reload must retain the exact policy, lease digest, and expiry of that
   page's consumption with nonregressing times.
5. Cache the exact Phase 4Q-selected source state for the one page description
   that may advance. The page adapter passes that cached prefix and
   authenticated source-head digest to Phase 4AA `claim`; the repository
   compares both under the shared account lock. A stale selection therefore
   fails before transition membership or a future-page claim can be recorded.
6. Keep Phase 4Q as the bounded inner selector. One Phase 4AB invocation can
   claim and execute at most one selected page, wait without provider I/O, or
   append one Phase 4P comparison. Waiting and comparison paths create no new
   page claim or consumption.
7. After Phase 4AA returns the selected claim, supply the unchanged Phase 4O
   runtime a claim-bound page-runtime adapter. Its sole `prepare_next` call
   invokes `prepare_claimed`, atomically inserts the canonical Phase 4O
   preparation and one-to-one consumption under the account lock, and requires
   exact readback before returning the unchanged preparation.
8. Close the claim/consumption transaction before Phase 4O resolves
   credentials, allocates request capacity, or performs provider I/O. Delegate
   Phase 4O `record` and `load_prefix` only after authenticating the exact
   consumption. A second preparation call or a crash after consumption cannot
   resend the stalled page.
9. Supply Phase 4O a restricted coordinator adapter pinned to the selected
   page consumption. Every revalidation must retain that exact fence,
   coordinator policy digest, lease digest, and expiry, must not predate the
   consumption, and must remain pre-expiry. Renewal or takeover before the
   request fails pre-transport; a later change may retain one raw-first
   response but cannot commit Phase 4O.
10. After the page workflow returns, require its receipt and the exact
    transition claim/consumption to reload unchanged. Phase 4Q then performs
    its existing exact selected append and unchanged-peer checks through the
    pair-authenticating loader.
11. Route comparison-only Phase 4P source loading through that same
    pair-authenticating loader. Every terminal page in both prefixes must
    reconstruct through its own Phase 4AA history before the comparison can be
    recorded or reloaded; no new claim is created on this path.
12. Reauthenticate both final source histories after Phase 4Q returns. For a
    page-advance result, require exactly one newly selected claim/consumption
    pair for the reported role and page. For wait or comparison, require no
    selected pair. Recheck every later-page claim against the final exact
    terminal earlier source before constructing the result.
13. Return a proof-constructed Phase 4AB result retaining the exact transition,
    unchanged Phase 4Q result, ordered earlier and later claim/consumption
    histories, and the optional selected claim/consumption pair. The evidence
    remains historical and non-authorizing.
14. Preserve all existing Phase 4Q and Phase 4O bounds and fail-closed
    semantics. Phase 4AB establishes no provider snapshot isolation or
    completeness, provider revision or execution identity, convergence,
    lifecycle application, reconciliation completion, readiness, submission,
    or trading authority.

## Consequences

The Phase 4AA page admission is composed through the unchanged Phase 4O
credential, budget, raw-first transport, commit, and reload path and the
bounded Phase 4Q selector. Every restarted source and Phase 4P comparison load
must authenticate the complete pair-managed page history. A stale Q-selected
prefix or source head loses before admission, while each admitted page carries
its own exact lease rather than imposing one lease on the entire paginated
capture.

No transaction spans provider I/O. One call remains bounded to one page,
no-I/O waiting, or one comparison, and a post-consumption crash remains stalled
without resend. Phase 4AB is still a local composition contract, not a deployed
reconciliation worker. Account/activity views, stream overlap,
provider-qualified revision/execution/correction identities, decode
quarantine, authoritative application, convergence, and Phase 4 readiness
remain open.
