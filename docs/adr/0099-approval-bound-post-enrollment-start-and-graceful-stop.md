# ADR 0099: Approval-bound post-enrollment start and graceful stop

- Status: Accepted (contract, dormant durable claim, and in-container barrier only;
  host execution blocked)
- Date: 2026-08-08
- Extends: [ADR 0098](0098-canonical-post-enrollment-start-evidence-review.md)

## Context

ADR 0097's single approved `new` operation established the external trusted-
head chain at sequence 1. ADR 0098 can authenticate the exact retained claim
and confirmed outcome and keep that historical launch distinct from a proposed
later launch. Neither result authorizes the normal supervisor.

The current normal runtime registers a new local epoch before it primes the
head-anchor worker. Starting that worker automatically queues a full-audit
`epoch_rotation` checkpoint, which can prepare sequence 2. The host launcher
also treats a running Compose topology as startup success and releases its
global lock without authenticating a sequence-2 terminal. Simply removing the
retained-claim quarantine would therefore cross the external mutation boundary
without a single-use approval, durable claim, or qualified outcome.

## Decision

Freeze a distinct post-enrollment start operation. Its exact approval binds:

- one UUIDv4 operation identity;
- the confirmed enrollment operation ID, claim SHA-256, outcome SHA-256, and
  reduced evidence SHA-256;
- the ADR-0098 review-projection SHA-256;
- one later Git revision, image-admission SHA-256, and immutable source and
  supervisor image IDs, distinct from the enrollment launch;
- every sequence-1 intent, receipt, readback, current-anchor, semantic,
  current-host-head, deployment-identity, and remote-namespace digest; and
- the only permitted first successor: exact integer sequence `2` with reason
  `epoch_rotation`.

The approval is single use. All readiness, operational-control, arming,
exposure, new-exposure, broker-action, alert-delivery, re-arm/resume, paper-
trading, and live-trading authority fields remain false. Start approval is not
trading authority, shutdown authority, or permission to create any successor
other than the bound sequence 2.

Before any epoch registration, signing, or provider mutation, the future
runtime must hold the host's global trusted-time launcher lock and freshly
reauthenticate the complete local SQL head plus a bounded stable full remote
audit. It must prove the exact retained sequence-1 intent and receipt, current
head and semantic digests, all deployment identities, one remote object, the
same stable namespace digest, no pending intent, no unanchored local suffix,
and no higher remote sequence. Fresh observation counts need not equal the
historical upload/idempotent counts; the immutable bytes and terminal state
must equal them.

The future launcher must use a staged release protocol:

1. create an admitted topology whose supervisor cannot register an epoch,
   sign, or contact the provider before an exact release marker;
2. authenticate retained enrollment evidence and the proposed launch, perform
   the fresh read-only runtime reauthentication, and retire all staged host
   inputs;
3. retain an owner-only mode-`0600`, `O_EXCL`, fsync-confirmed start claim that
   binds the exact approval and fresh reauthentication digest;
4. revalidate every approval, image, daemon, topology, mount, and retained-
   evidence binding, then publish the one exact release marker;
5. require the runtime to register its epoch and confirm sequence 2 as
   `epoch_rotation`; and
6. authenticate that SQL/remote successor and the still-qualified persistent
   topology before retaining a content-addressed confirmed host outcome.

Compose `running` state is never a confirmed start outcome. Before claim and
release, failure must tear down without sequence 2. Once the claim is retained,
any uncertain release, runtime exit, sequence-2 result, teardown, outcome
retention, or lock release consumes the approval and is recovery-required. A
missing confirmed outcome must never be retried as a new start. Recovery needs
a separately reviewed approval bound to the exact claim, outcome if any, SQL
state, remote state, and topology state.

Graceful shutdown is a separate single-use operation. It must bind the exact
confirmed start outcome and active immutable topology, take the same global
launcher lock, and signal the supervisor before the source. The supervisor must
finish in-flight work, authenticate and confirm one exact `clean_stop`
successor, and expose a bounded terminal result. Only after the host freshly
authenticates that SQL/remote successor may it stop the supervisor, then stop
the Chrony source and remove the project network while preserving both named
volumes. It must never use `down --volumes`. Any uncertain clean-stop or
teardown result is retained as nonconfirmed evidence and requires review, not
an automatic stop retry.

The implementation now contains the dependency-neutral, non-authorizing
approval, claim, reauthentication, successor-candidate, and unconfirmed-outcome
projections plus the reusable read-only sequence-1 observation path. It also
contains two independently fail-closed primitives:

- a dormant owner-only mode-`0600`, `O_EXCL`, fsync-confirmed retained-claim
  writer that preserves the exact claim bytes and inode identity without
  granting release, sequence-2, shutdown, control, or trading authority; and
- an atomically published, fixed in-container release-marker writer/reader and
  bounded waiter. The normal supervisor waits after staged inputs are loaded
  and marked consumed, but before signal-handler installation, SQL engine or
  provider composition, epoch registration, signing, or provider access.

No supported host launcher calls the claim writer or publishes the release
marker. There is no staged-topology controller, retained-evidence/approval
wiring, `docker exec` release, confirmed start outcome, or graceful-stop
operator. `trusted-time-start` and shutdown remain hard closed. Building and
executing the remaining protocol requires a later exact
revision/image/admission tuple and separate operational approval.

## Consequences

The runtime now has an explicit pre-mutation barrier, and the dormant claim
writer freezes the required exclusive durability semantics. Neither primitive
connects approval to a staged container, so container creation and marker
capability still are not authorization or success. The already-retained
enrollment evidence remains historical proof; it is never rewritten, deleted,
or used as an implicit start permit.

No sequence 2, persistent topology, `clean_stop`, provider-terminal observer,
watchdog deployment, readiness, alert delivery, new-exposure gate, trading
authority, or Phase 6 exit evidence is created by this ADR.
