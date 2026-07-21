# ADR 0027: source-bound execution settlement ledger

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0025 posts executions on trade date, and ADR 0026 projects FIFO lots and
trade-date account economics. A cash account still needs to distinguish an
execution's economic cash movement from actual settlement. Treating unsettled
sale proceeds as buying power or ignoring an unsettled purchase obligation would
overstate available cash and make later risk decisions unsafe.

The repository does not yet have an authoritative exchange calendar or broker
settlement feed for execution effects. Settlement timing therefore cannot be
inferred from ambient dates or an assumed T+N rule. Corrections also need their
own settlement deltas: an initial fill can settle before a later price,
quantity, fee, or bust adjustment.

## Decision

1. Add a pure, account-bound settlement-ledger reducer layered over the exact
   ADR 0025 trade-date ledger. Require the stable account identity, bind it into
   the projection, keep the original entries unchanged, and add balanced
   settlement reclassification and confirmation entries.
2. Require one immutable instruction for every execution-revision cash delta.
   The instruction binds the exact broker event ID and semantic digest, carries
   an explicit contractual settlement time and record time, and has a stable
   external identity. Zero-cash deltas require no instruction.
3. At trade time, reverse the execution's trade-date cash movement into an
   explicit receivable for positive cash deltas or payable for negative cash
   deltas. Before confirmation, settled cash therefore excludes both unsettled
   sale proceeds and unsettled purchase disbursements.
4. Confirm actual settlement with a separate immutable fact bound to the exact
   instruction digest. Confirmation clears that revision's receivable/payable
   against cash. Actual and recorded UTC times remain explicit; no calendar or
   wall-clock inference occurs.
5. Treat each execution correction as its own predecessor-relative cash delta.
   It may create a receivable even when the original buy created a payable, or
   vice versa. Settling one revision does not imply that any later correction
   settled.
6. Project trade-date cash, settled cash, receivables, payables, and conservative
   available cash. Available cash equals settled cash less open payables and
   never nets unsettled receivables into buying power.
7. Collapse exact duplicate order, cash-flow, instruction, and confirmation
   delivery. Reject missing or unexpected instructions, conflicting external or
   source identities, cross-order execution-ID reuse, forged digests, unknown
   confirmations, invalid account orientation, and temporal regressions.
8. Make the canonical settlement state proof-constructed by the reducer rather
   than publicly instantiable. Re-derive its canonical instructions,
   confirmations, entries, obligations, balances, cash views, and observation
   time from retained source evidence during construction and revalidation;
   callers cannot inject a forged balance or use `dataclasses.replace` to create
   one.
9. Extend the architecture guard so the reducer cannot acquire filesystem,
   process, network, thread, randomness, calendar, or ambient wall-clock
   authority.

## Consequences

Later risk code can consume an explicit conservative cash boundary rather than
guess whether ledger cash is settled or available. Late corrections and busts
remain append-only and independently settleable, while the original trade-date
financial transcript remains intact.

This contract does not choose business-day calendars, infer T+1, post interest,
model settlement failure, or reconcile a broker statement. Dividends, splits,
position transfers, corporate-action corrections, durable settlement tables,
atomic batch risk, coordinator fencing, broker effects, and trading authority
remain gated.
