# ADR 0031: process-local account coordinator leases and fences

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0030 serializes batch-risk reservations inside one runtime, but it does not
establish which worker owns the right to cross a broker boundary. A risk
authorization can remain exact while a stale worker, a replacement worker, or
two independently constructed broker clients race to submit it. Checking an
ownership flag before calling a broker is insufficient because release or
handoff could interleave between that check and the side effect.

ADR 0004 requires a renewable account lease, monotonically increasing fencing
generation, and ownership revalidation before every broker side effect. The
current phase is still deterministic local simulation, so this slice must prove
the in-process contract without claiming database, crash, failover, paper, or
live safety.

## Decision

1. Define a pure account-coordinator contract with a versioned timing policy,
   immutable lease revisions, stable fencing generations, exact lease-bound
   fences, point-in-time validation receipts, and explicit clean-release facts.
   The policy fixes the lease TTL, maximum in-flight duration, and future
   takeover safety interval; the safety interval must exceed the maximum
   in-flight duration.
2. Bind every coordinator instance to one account and one authority-owned policy
   and clock. Callers cannot inject the current time or lease duration per
   operation. A strong process-local account registry retains the last fencing
   generation and rejects a second authority for the same account, even after a
   clean release.
3. The first acquisition receives generation one. An exact active acquisition
   retry by the same owner returns the existing lease; a competing owner fails.
   Renewal requires the exact current unexpired fence, extends the expiry, keeps
   the acquisition identity and generation, and updates the immutable lease
   revision. The stable fence remains usable by the same owner; every validation
   receipt binds the exact current lease digest and expiry.
4. Validation requires the exact account, owner, lease, and generation, then
   re-reads the current lease revision. Expired, released, foreign, or forged
   fences fail closed. Trusted clock regression also fails closed. Receipts and
   release facts are proof-constructed by the coordinator rather than publicly
   shape-constructible.
5. `run_fenced` holds the account transition lock while it samples trusted time,
   validates the current fence, and invokes the protected callback exactly once.
   The supplied `FencedBrokerPort` keeps that lock across the complete delegate
   `submit` call and returns the result with its fence receipt and exact request
   binding. Reentrant lease transitions are rejected while the callback runs. A
   separate precheck followed by an unlocked call is forbidden because it would
   create a time-of-check/time-of-use race.
6. Clean release is allowed only for the exact current unexpired fence and is
   idempotent. A later deliberate acquisition increments the generation, so the
   old owner can never regain authority with a retained fence. Release cannot
   interleave with a protected operation.
7. Expiry is not permission for automatic failover. An abandoned expired lease
   remains owned and blocks renewal, release, broker effects, and new acquisition.
   Durable manual takeover will require lease expiry, the safety interval,
   process-stop confirmation where possible, reconciliation, and human re-arm;
   those facts do not yet exist and are not invented here.

## Consequences

Simulation can now place the complete broker call behind one account fence, and
parallel process-local owners cannot both act. Renewal, clean handoff, and stale
worker rejection are deterministic under injected time, while generation never
resets for the life of the process.

This contract is deliberately not a durable coordinator. Process death loses
the current lease record, and the broker cannot enforce the fence. SQL leases,
heartbeat ownership, manual takeover evidence, atomic batch/order preparation,
submission attempts, unknown-submission recovery, reconciliation, reservation
release, and crash-boundary tests remain required before paper execution. No
paper/live adapter or trading authority is enabled.
