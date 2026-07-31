# ADR 0069: restart-safe UNKNOWN recovery composition

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4J durably schedules one-shot client-order lookups, Phase 4I retains an
authenticated lookup receipt, Phase 4K normalizes that receipt as
non-applying reconciliation evidence, and Phase 4L admits the fact to a
source-scoped inbox without applying it. Those four boundaries are
individually idempotent, but calling them as unrelated jobs leaves three
important restart prefixes:

1. Phase 4I may commit before Phase 4J attaches the receipt to its dispatch.
2. Phase 4J may attach a receipt before Phase 4K records the normalized fact.
3. Phase 4K may commit before Phase 4L records its non-application decision.

The original Phase 4J public history exposes only event digests, and Phase 4I
loads only by receipt UUID. A restarted worker therefore could not discover
the first prefix from the deterministic delivery identity already frozen in
the Phase 4J ticket. A naive wrapper could also evaluate the next schedule
slot before older durable receipts were fully accounted through Phase 4L.

No database transaction can safely span credential resolution, broker I/O,
normalization, and inbox admission. Restart safety must instead come from
authenticated source-indexed reads, deterministic identities, idempotent
writes, and a fixed composition order.

## Decision

1. Define Phase 4AC as the
   `phase4ac-unknown-recovery-evidence-pipeline-v1` application contract. It
   composes the existing Phase 4J, 4I, 4K, and 4L contracts and adds no table,
   migration, provider endpoint, retry slot, lifecycle transition, or trading
   authority.
2. Require the schedule, lookup executor, authenticated lookup repository,
   submission-attempt loader, raw-ingress loader, reconciliation repository,
   and inbox repository to expose one exact positive process-local durable
   store identity. Validate every required method and require all identities
   to match before a durable read, trusted-clock access, credential lookup, or
   broker effect.
3. Add a proof-constructed Phase 4J progress projection. It carries the exact
   durable plan and ordered dispatch claims, each with its fully authenticated
   Phase 4I receipt when one has been attached. Construct it only after
   authenticating the complete schedule history, account fence evidence, and
   attached lookup source chain.
4. Add an authenticated Phase 4I lookup by raw-ingress receipt identity. The
   Phase 4J ticket's deterministic delivery ID is exactly that ingress
   identity. A restarted worker uses it to discover a lookup that committed
   before the Phase 4J observation acknowledgement; it then attaches the
   identical receipt through the unchanged Phase 4J recorder without another
   broker request.
5. Add authenticated Phase 4K and Phase 4L reads by their immediate source
   identities. A lookup receipt selects at most one reconciliation fact, and a
   reconciliation fact selects at most one inbox decision. Each read
   authenticates the complete account-local history and durable source chain.
6. Before evaluating another Phase 4J slot, traverse all attached dispatches
   in schedule order. For each receipt, reload or idempotently create its
   unchanged Phase 4K fact, then reload or idempotently create its unchanged
   Phase 4L decision. Any missing, corrupt, substituted, or cross-account
   source fails closed and no new lookup is issued.
7. Invoke the unchanged Phase 4J one-step workflow only after that durable
   prefix is fully accounted. It may wait, report an active claim, report a
   terminal schedule state, or consume and execute at most one new Phase 4I
   lookup.
8. After the Phase 4J step, repeat the bounded attachment pass once. This
   catches both the newly returned lookup and an active-claim receipt that
   became durable concurrently. Replay the final attached prefix through the
   same idempotent Phase 4K/4L path.
9. Return a proof-constructed result containing the exact Phase 4J result and
   ordered `(ticket, lookup receipt, reconciliation fact, inbox decision)`
   chains. Do not claim whether a downstream write was new: existing Phase 4K
   and 4L retry APIs intentionally return the identical durable fact.
10. Keep every authority flag false. Phase 4AC does not resolve an UNKNOWN
    submission, apply an inbox fact, release a reservation, produce a canonical
    execution, authorize resubmission, establish reconciliation convergence,
    or enable paper startup.

## Consequences

A process kill after Phase 4I persistence, after Phase 4J acknowledgement,
after Phase 4K normalization, or after Phase 4L admission can resume without
losing evidence or sending an unaccounted additional lookup. Existing exact
retries remain clock-free where their underlying repositories already provide
that guarantee, and all source corruption is detected through the original
authenticated histories.

The pipeline remains bounded and local. It does not deploy a worker or secret
resolver, qualify provider revision or execution identities, apply broker
facts, reconcile the whole account, or close the Phase 4 exit gate. Account
activity/fill pagination, stream overlap, authoritative application, and
convergence remain the next dependencies.
