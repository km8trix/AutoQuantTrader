# ADR 0028: source-bound corporate-action accounting

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0019 qualifies retained `divCash` and `splitFactor` values only as corporate-
action candidates. It does not make a market-data vendor authoritative for
security entitlements. ADR 0025 and ADR 0026 therefore exclude dividends and
splits from the append-only ledger and FIFO account projection.

The first corporate-action accounting slice must add those effects without
silently treating a revised announcement as a second action, inventing an order
for simultaneous facts, rounding cost basis, or valuing post-split shares with a
pre-split mark. It must preserve the existing long-only, whole-share cash-account
boundary and remain deterministic under duplicate delivery and ambient decimal-
context changes.

## Decision

1. Add a pure corporate-action ledger overlay for explicitly admitted stock-
   split and cash-dividend facts, and integrate that exact overlay into the FIFO
   account projection. Construction of an accounting fact records an admission
   decision; retained vendor candidate fields alone grant no such authority.
2. Give every action a stable source action identity distinct from its source
   revision identity and content digest. Derive the accounting action identity
   from the stable source action identity, bind the revision and digest into its
   semantics, collapse exact redelivery, and reject reuse of an action, revision,
   or immutable identity with conflicting meaning.
3. Do not interpret corrected corporate-action revisions in this slice. More
   than one non-identical revision for the same stable action fails closed rather
   than posting both revisions, reversing an earlier entry, or guessing which
   revision is authoritative.
4. Reconcile each action's explicit entitled quantity against causal security
   units at its effective UTC time. Replay base-ledger unit deltas and preceding
   splits in the corporate-action reducer, then independently reconcile the same
   entitlement against the FIFO lot book. Reject an action that shares an
   effective time with a position change, multiple splits at one instrument/time,
   or a split and dividend at one instrument/time; no identifier-based tie-break
   may manufacture economic ordering.
5. Support positive non-neutral whole-number split ratios only when both the
   aggregate entitlement and every affected FIFO lot produce whole shares.
   Record the split as an append-only unit effect. Fractional shares, aggregation
   across fractional lots, and cash-in-lieu are unsupported and fail closed.
6. Preserve each FIFO lot's exact total cost basis across a split and derive unit
   or average cost from quantity and total basis. A later partial-lot sale uses a
   proportional basis allocation only when that allocation fits
   `NUMERIC(28, 10)` exactly; the projector never rounds or silently discards a
   residual basis amount.
7. Require every open post-split position to have a mark whose effective time is
   strictly later than the latest split. A pre-split or same-time mark is
   scale-ambiguous and cannot value the changed share count.
8. Accrue a cash dividend as a debit to dividend receivable and a credit to
   dividend income using the admitted per-share amount and reconciled
   entitlement. Record receipt with a separate immutable payment fact bound to
   the exact accrual digest; it cannot precede the payable time or its accrual's
   recorded time and clears receivable into cash without recognizing income a
   second time.
9. Project dividend income and unpaid receivable into instrument and account
   results, include the receivable in equity, reconcile cash, units, fees, and
   income to the overlaid ledger, and keep all identities, ordering, arithmetic,
   and semantic digests context-independent. Extend the architecture guard so
   this code cannot acquire filesystem, process, network, thread, randomness, or
   ambient wall-clock authority.

## Consequences

The Phase 2B account can now replay admitted whole-share forward and reverse
splits without changing FIFO basis, and can distinguish earned dividend income
from unpaid receivable and received cash. Stable action identities prevent a new
source revision from becoming an accidental second economic event. Explicit
entitlements, unambiguous effective times, and post-split marks make ledger and
valuation failures visible instead of hiding them behind ordering or rounding.

This is not corporate-action discovery or authorization. Corrected action
revisions, fractional shares, cash-in-lieu, return of capital, stock dividends,
withholding and tax treatment, partial dividend payments, mergers, symbol
changes, delistings, position transfers, multi-currency translation, durable
corporate-action tables, broker reconciliation, broker effects, and trading
authority remain gated.
