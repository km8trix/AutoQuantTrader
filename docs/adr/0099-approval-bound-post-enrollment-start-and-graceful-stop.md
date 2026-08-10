# ADR 0099: Approval-bound post-enrollment start and graceful stop

- Status: Accepted (contract, dormant globally fixed claim/barrier, read-only
  sequence-2 observation/binding, import-only claimed-release handoff, and
  pure never-started and staged-unreleased topology snapshots; host execution
  blocked)
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
contains five independently fail-closed protocol seams:

- a dormant, globally single-use fixed owner-only mode-`0600`, `O_EXCL`, fsync-
  confirmed retained-claim writer. A stable bounded inventory rejects any
  existing fixed-name or legacy per-operation claim before retention, and
  revalidation requires the fixed claim to remain the only recognized claim;
- an atomically published, fixed in-container release-marker writer/reader and
  bounded waiter. The normal supervisor waits after staged inputs are loaded
  and marked consumed, but before signal-handler installation, SQL engine or
  provider composition, epoch registration, signing, or provider access; and
- an import-only claimed-release handoff whose future caller must already hold
  the global launcher lock. It accepts only a syntactically valid full container
  ID candidate, checks the exact retained enrollment before reauthentication
  and again before and after claim retention, consumes and closes its read-only
  sequence-1 issuer before retention, rechecks the empty claim slot, and
  durably retains and revalidates the claim against its canonical owner-only
  artifact root; and
- a pure, import-only created-topology candidate validator. It accepts only two
  equal submitted full-ID project inventories, two equal structurally valid local-daemon
  projections, two equal stable named-volume identity projections, the exact
  approved launch and image configurations, two inspections keyed by their
  IDs, and all four non-optional staged input paths. It derives source and
  supervisor roles from exact Compose labels, not caller ordering, and requires
  each execution-bearing Docker state field to prove a never-started `created`
  container. Missing nullable evidence, type-confused numeric values, unsafe
  namespace/device/DNS/sysctl/logging/proc-policy values, ambiguous or repeated
  staged paths, and command/stop-policy drift fail closed before it returns
  separate inert source-first start argv values; and
- a second pure, import-only staged-unreleased candidate validator. It binds one
  exact prior created-topology snapshot to caller-supplied running source and
  supervisor projections, equal before/after exact consumed-input-marker
  candidates, both fixed release paths absent, and four retired staged-host-
  input projections. The running state must remain nonterminal and unrestarted,
  with the source healthy.

The handoff returns only `claimed_release_handoff_unqualified` and these exact
inert argv elements, in order: `docker`, `container`, `exec`, `--user`,
`10001:10001`, the full 64-character lowercase-hex container-ID candidate, and
`/opt/venv/bin/autoquant-trusted-time-post-enrollment-release`, with no
additional arguments. It authenticates neither container nor topology identity;
`container_identity_authenticated` and `topology_authenticated` remain false.
The ID remains untrusted until a future executor independently revalidates the
exact topology immediately before release. The handoff never executes or
inspects Docker, creates a topology, publishes the release marker, observes or
mutates sequence 2, retains an outcome, or exposes a CLI. Every authority
property remains false.

The created-topology contract is
`phase6d-post-enrollment-start-created-topology-snapshot-v1`. It binds the
operation, approval, review, confirmed-enrollment evidence, proposed immutable
launch, daemon identity, both stable volume identities, the exact two-container
inventory, and SHA-256 projections of the same isolated inspection and image-
configuration copies that passed validation. Raw environment, mount, staged-
path, state, inspection, and image-configuration objects are not retained. Its
only status is `created_topology_snapshot_unqualified`; submitted-inventory,
daemon, volume, container, and topology authentication remain false because the
pure function does not own the Docker reads. Claim retention, topology
mutation, both container starts, release, persistent start, sequence 2,
shutdown, and every trading or operational authority remain false.

Contract
`phase6d-post-enrollment-start-staged-unreleased-topology-snapshot-v1` defines
the next semantic state without observing it. It requires the exact prior
created snapshot and same operation, approval, immutable launch, daemon,
volumes, inventory, container identities, and image-configuration projections.
Both submitted inspections must prove an exact running, nonpaused,
nonrestarting, non-OOM, nondead, error-free, zero-restart topology; the source
must be healthy. Equal submitted before/after candidates must show the fixed
database-secret-consumed marker with exact metadata and digest, both fixed
release paths absent, and all four exact staged host inputs retired. This is
only caller-supplied evidence. Its status is
`staged_unreleased_topology_snapshot_unqualified`, and every observation-
provenance, created-topology, daemon, volume, inventory, container, topology,
database-secret-consumption, release-absence, staged-input-retirement, source-
start, supervisor-start, and start-order authentication field remains false.

Neither topology validator performs file, clock, Docker, subprocess, claim,
release, SQL, provider, or persistence operations. Neither retains raw
inspection, image-configuration, marker, staged-path, environment, mount, or
state objects. The next implementation must be a strict bounded read-only
Docker issuer that rejects duplicate JSON keys before decoding and targets both
the created and staged-unreleased contracts under the same qualified-daemon
lock. A later pure fence composition must bind the created snapshot and equal
staged snapshots obtained immediately before claim retention and release.
Ordinary pre-claim drift must fail before consuming the globally single-use
claim. Only after those boundaries exist may a separately admitted and
operationally approved active controller execute any projected argv.

The dormant sequence-2 issuer performs complete SQL replay, a stable bounded
two-object remote audit, and complete SQL replay again without signing or
uploading. It freezes the exact sequence-2 `epoch_rotation` receipt, record, and
confirmed-anchor ordinal while allowing independently authenticated local probe
suffixes to advance monotonically. Any uncertain SQL or provider result becomes
a fatal postconditions-unconfirmed result. The pure binder requires the claim's
sequence-1 predecessor and all nine identity digests and yields only
`successor_candidate_unqualified`; it does not qualify the host outcome, which
remains `UNCONFIRMED`, and all authority fields remain false.

No worker/main, Make, Compose, or supported host-launcher path calls the
sequence-2 issuer or binder, invokes the claimed-release handoff or created-
topology or staged-unreleased snapshot, executes either projected argv, invokes
the claim writer, or publishes the release marker. There is no staged-topology
controller, bounded Docker observation issuer, fence composition, retained-
evidence/approval wiring, Docker execution, sequence-2 runtime mutation,
confirmed start outcome, or graceful-stop operator. `trusted-time-start` and
shutdown remain hard closed. Building and executing the remaining protocol
requires a later exact revision/image/admission tuple and separate operational
approval.

## Consequences

The runtime now has an explicit pre-mutation barrier, and the dormant claim
writer freezes the required exclusive durability semantics in one global fixed
slot while treating every legacy per-operation claim as consumed authority.
Neither that seam, the import-only handoff, nor either pure topology snapshot
connects approval to an active Docker observation or staged container, so a
projected Docker argv, caller-supplied inspection or marker state, container
creation, and marker capability still are not authorization or success. The
already-retained enrollment evidence remains historical proof; it is never
rewritten, deleted, or used as an implicit start permit.

The new observer can authenticate only an already-existing exact sequence-2
state; it cannot create that state or qualify topology, release, start outcome,
or shutdown.

No sequence 2, persistent topology, `clean_stop`, provider-terminal observer,
watchdog deployment, readiness, alert delivery, new-exposure gate, trading
authority, or Phase 6 exit evidence is created by this ADR.
