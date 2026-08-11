# ADR 0099: Approval-bound post-enrollment start and graceful stop

- Status: Accepted (contract, dormant globally fixed claim/barrier, read-only
  sequence-2 observation/binding, import-only claimed-release handoff, pure
  topology snapshots, bounded observation issuer, and pure two-stage same-
  session topology fence plus code-only claimed pre-release chronology and
  callback-scoped lease/deadline, retained recovery-outcome, and final claimed
  action-time topology-fence seams; host execution blocked)
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
state objects.

The separate dormant raw issuer now implements contract
`phase6d-post-enrollment-topology-observation-reader-v1`. Its production open
owns the global launcher lock, pins one canonical absolute Docker executable,
local Unix socket, and daemon identity, and binds one non-copyable session to
its creating process with serialized lifecycle state. Its guarded production
signer is bound to the exact issuer owner, session, and creating PID. The
lifecycle still serializes each raw observation or cursor operation outside a
consumed choreography. The additive private `_run_exclusive_choreography`
callback may be acquired exactly once and only while the issuer is fresh: it
must have no prior created or staged observation, cursor, active operation, or
consumed choreography. Its opaque token is bound to the exact issuer,
authentication capability, session, creating PID, and exact current-thread
identity. It cannot be copied or serialized, is valid only inside that callback, and
is revoked before callback return can escape. A child at-fork hook closes the
inherited global-lock descriptor without acquiring inherited Python locks.

The callback fixes one absolute 300-second monotonic deadline at acquisition.
Every checkpoint rejects clock regression and treats equality with the deadline
as expired. Raw Docker reads retain their two-second deadline; leased Docker
reads instead receive `min(2 seconds, remaining time)` and checkpoint again
after the command. The unchanged v1 transcript's
`timeout_milliseconds=2000` records the authenticated ceiling, not a claim that
a smaller leased runner timeout was not applied. A raw observation or cursor
call with no exact token while
the callback is active, or an attempted `close`, poisons the issuer and revokes
its capabilities. That interference cannot release the outer flock before the
callback unwinds. Every fixed observation also has independent byte bounds.
The decoder accepts only compact LF-terminated UTF-8 JSON and rejects duplicate keys,
nonstandard constants, floats, oversized integers, invalid Unicode, and
depth/node exhaustion.

That same acquisition fixes the recovery-retention deadline from the identical
monotonic origin at `start + 305 seconds`. It is an absolute outer bound: claim
retention, lease poison, action-deadline expiry, recovery-capability arming, and
retention start never reset it. Equality is expired at both `start + 300
seconds` for every action and `start + 305 seconds` for recovery retention. An
`unbound` or `claim_admitted` recovery capability is revoked by action poison or
the 300-second equality boundary and cannot be armed during the outer interval.

The created path performs 14 reads and each staged path performs 16. Both bind
stable daemon, named-volume, exact two-container inventory, separately observed
bridge network, immutable image root, and exact raw container boundaries. The
staged path also performs two fixed descriptor-held, read-only in-container
marker/absence probes and validates the container state after both probes have
exited; retired host inputs are observed only through owner-only no-follow
directory descriptors. One created envelope may be followed by at most two
ordered staged envelopes. Ordinal 1 chains to the created observation, ordinal
2 chains to ordinal 1, and both staged snapshots must retain one equal stable
snapshot digest.

The issuer's `issue_observation_cursor` method emits contract
`phase6d-post-enrollment-topology-observation-cursor-v1`, with sole status
`topology_observation_cursor_unqualified`. Each process-HMAC-sealed cursor uses
one bounded daemon read and revalidates the PID-bound issuer, global lock,
executable, socket, daemon, and session. It binds its cursor ordinal, staged
count, created and last observation identities, and first staged snapshot
digest. At most three ordered cursors may be issued. They authenticate reader
position only, not freshness or authority. Each cursor is bound to its exact
registered object identity in the originating process, is non-copyable and
nonserializable, and is invalid after fork.

Only those opaque, payload-bound outer envelopes authenticate lock/daemon
observation provenance. They retain no raw response, secret, staged path, or
mutable inspection and leave topology authentication plus every claim, start,
release, sequence-2, shutdown, operational, and trading authority false. The
issuer has no CLI, worker, controller, provider, SQL, claim writer, topology
mutation, start, release, or outcome-persistence surface.

Two pure import-only contracts compose that sealed observation chain. The
pre-claim contract is
`phase6d-post-enrollment-start-pre-claim-topology-fence-v1`, and its only status
is `pre_claim_same_session_topology_fence_unqualified`. It reauthenticates the
exact created envelope and staged ordinal 1, then binds the equal session,
created-observation identity, ordinal-1 direct predecessor, approved launch,
container/topology identity projections, and staged snapshot digest.

The pre-release contract is
`phase6d-post-enrollment-start-pre-release-topology-fence-v1`, and its only
status is `pre_release_same_session_topology_fence_unqualified`. It
reauthenticates the exact pre-claim fence and staged ordinal 2, requires ordinal
2 to name ordinal 1 as predecessor, and binds the same session, created
observation, approved launch, topology identity projections, and unchanged
staged snapshot digest across both stages. Malformed, forged, cross-session,
out-of-order, forked, or drifted candidates fail closed.

The two fence results authenticate only the opaque process-private observation
envelopes and their submitted same-session chain and equality relationships.
They do not authenticate a current topology for an action, time, freshness,
claim retention, or temporal adjacency to release. Because these functions are
pure, staged ordinal 2 may have been issued and cached before claim retention;
a structurally valid pre-release result does not prove otherwise. Neither
binder performs Docker, file, clock, subprocess, claim, release, SQL, provider,
or persistence I/O. Claim retention, topology mutation, both starts, release,
persistent start, sequence 2, shutdown, outcome retention, and every operational
or trading authority remain false.

The code-only claimed chronology seam is contract
`phase6d-post-enrollment-start-claimed-pre-release-topology-fence-v1`, with sole
status `claimed_pre_release_topology_fence_unqualified`. It accepts the exact
pre-claim fence only while the same live issuer reports staged count 1.
Function `prepare_post_enrollment_start_claimed_pre_release_fence` enforces:
exact approval binding and descriptor-anchored live absence of all four staged
inputs; first consecutive count-1 cursor and pre-claim validation; real claim
retention and revalidation through the claimed-release handoff; second consecutive cursor
still at count 1; issuer-created staged ordinal 2; pre-release binding; third
consecutive cursor at count 2 with ordinal 2 last; and final exact-claim
revalidation. It accepts no caller-supplied ordinal 2, so cached or preissued
ordinal 2 evidence, a preadvanced or nonconsecutive cursor, another issuer
session, chain drift, a mismatch between the full ordinal-1 and ordinal-2
observations, or claim drift fails closed. This rejects preissued ordinal 2 only
within this preparation call. The third cursor performs one daemon/session read,
not another full topology observation, so topology drift after ordinal 2 is not
detected. Called directly, this original preparer retains its prior raw,
per-operation behavior and does not prove uninterrupted issuer ownership.

The additive
`prepare_post_enrollment_start_leased_claimed_pre_release_fence` wrapper runs
that unchanged v1 chronology and returns the same exact v1 result and public
payload. It accepts only the exact private callback token and checkpoints it
before structural preparation, immediately before and after the claimed-release
handoff, after final claim revalidation, and after result construction. All
leased cursor and ordinal-2 Docker reads also use the lease checkpoints and
shrinking command timeouts. The lease, its private digest and monotonic fields,
and the checkpoints are not added to the claimed-fence payload and are not
durable evidence. The returned result neither retains the token nor proves that
the callback or issuer remains active.

This process-sealed seam authenticates observation provenance, same-session
chain and stable-topology equality, real claim retention and chronology,
ordinal 2 after the claim, and the final cursor session. Its result is bound to
its exact registered identity in the originating process, is non-copyable and
nonserializable, and is invalid after fork. Public authenticated payload
projection revalidates that exact type, process seal, and nested evidence; it is
not durable evidence. It
authenticates no freshness or current topology for an action. It may retain the
globally single-use claim and perform the reader's bounded ordinal-2
observations, but it does not publish the marker, execute release, mutate
topology, start a container,
observe or create sequence 2, qualify persistent topology, retain an outcome,
or grant any operational or trading authority. Once claim preparation begins,
every later failure is recovery-required because this seam cannot establish
claim absence versus retention after that boundary. A crash may leave only the
durable consumed claim; no chronology/release result can be reloaded and no
recovery command exists. The result is never a release or retry permit.

The additive dormant recovery-outcome seam implements contract
`phase6d-post-enrollment-start-retained-recovery-outcome-v1`, whose only status
is `recovery_required`. The private
`_run_exclusive_choreography_with_recovery_retention` wrapper creates one exact
callback-local, PID/thread/session-bound, non-copyable recovery-retention
capability alongside the action lease. Before claim preparation, the claimed-
chronology seam mints a non-copyable, nonserializable one-shot authorization
bound to the exact issuer, lease, recovery capability, artifact and ignored
roots, PID, and thread. The reader consumes that exact tuple before registering
an opaque binder; forgery, substitution, replay, or direct issuance fails
closed. A `finally` edge removes the authorization whether the reader consumes
it or issuance raises any ordinary or asynchronous failure first. The claim
writer accepts only that binder and checkpoints the exact live action lease,
flock, roots, and absolute action deadline immediately before its exclusive
`O_EXCL` creation boundary. That successful checkpoint is the only transition
from `unbound` to mandatory one-way `claim_admitted`; binding refuses a binder
that skipped it. After the first exact post-retention revalidation, binder
consumption revalidates the claim, flock, deadline, and registration, arms the
capability with that exact receipt while atomically revoking the binder, then
revalidates the claim again. Any pre-arm failure, including asynchronous
interruption, revokes and poisons; any post-arm failure marks retention
`unconfirmed`. It cannot execute a caller-chosen callback. If the exact retained
claim receipt is absent or unavailable at outcome preflight, no recovery-outcome
write begins.

At action poison or the `start + 300 seconds` equality boundary, every Docker,
observation, cursor, release, provider, SQL, and other action authority is
revoked immediately. While the same owning callback and outer flock remain
live, the armed recovery capability is the sole non-action exception. Function
`retain_post_enrollment_start_recovery_required_outcome` may consume it exactly
once, before the unchanged `start + 305 seconds` equality boundary, to retain
one content-addressed, owner-only pre-release recovery disposition bound to the
exact claim. It cannot unlink or replace an artifact, retry retention, inspect
or mutate topology, publish release, create sequence 2, restore the action
lease, or confer operational or trading authority. Starting retention at or
after the outer deadline performs no write. If a started write cannot be
confirmed before that deadline, the capability remains consumed, any possibly
durable artifact is never unlinked, and the retained claim remains the hard-
closed recovery fact. Completion is bound to a final exact revalidation of the
outcome receipt and inode. Claim or outcome loss after exclusive creation begins
therefore preserves any possibly durable artifact but reports retention as
unconfirmed, never as terminal retained success.

The distinct final action-time reader contract is
`phase6d-post-enrollment-final-action-topology-observation-v1`, with sole status
`final_action_staged_unreleased_topology_observation_unqualified`. It does not
widen the staged v1 chain: after staged ordinal 2 and all three cursors, private
method `_issue_claimed_final_action_topology_snapshot` accepts only a one-shot
authorization bound to the exact claimed pre-release object and digest, created
observation, approval, approved launch, staged-path tuple, issuer, active lease,
PID, and thread. A `finally` edge removes any authorization that issuance does
not consume. The reader performs one new complete 16-read staged-unreleased
observation under the shrinking action deadline. It independently revalidates
the claimed type/process seal and private created, ordinal-2, and cursor-3
identities; requires staged count 2, cursor count 3, ordinal 2 last, the same
first staged snapshot, and no prior final observation; and issues neither staged
ordinal 3 nor cursor 4.

Contract `phase6d-post-enrollment-start-claimed-action-topology-fence-v1`, with
sole status `claimed_action_topology_fence_unqualified`, binds that final full
observation back to the exact process-sealed claimed pre-release fence.
Function `prepare_post_enrollment_start_leased_claimed_action_topology_fence`
accepts only that exact result and its one-shot process-private origin tuple:
issuer, lease, armed recovery capability, artifact and ignored roots, PID, and
thread. The claimed result's capability registry, not either public payload,
holds that tuple until the action preparer consumes it. Successful consumption
erases the full issuer/lease/recovery/root/PID/thread tuple before the final read
and retains only a weak reference to the originating issuer as a consumed-origin
tombstone. The tombstone grants no authority and exists solely so a later replay
can still poison the origin. Wrong or replayed tuples poison the registered or
tombstoned origin. After consumption, the preparer repeatedly requires the exact
recovery capability to remain armed while revalidating the live lease, named
lock, roots, and shrinking deadline. It revalidates the exact
retained claim before and after the reader operation and checkpoints both the
armed recovery escape and lease through result construction. The result is
process-local, non-copyable, nonserializable, and invalid after fork. Its public
payload retains only digest projections; the in-process object retains sealed
nested evidence for revalidation. It retains neither the lease nor recovery
capability and does not prove authority survives after return. Current-session,
freshness, and topology authentication remain false; it does not prove temporal
adjacency to release.

Invalid input before the exact claimed fence is established is rejected. Once
that exact object is presented, a missing, wrong, or replayed origin tuple is
recovery-required and poisons its registered originating action; an exact
candidate issuer is poisoned as well. Any later observation, claim, armed-
recovery, lock, deadline, checkpoint, or result failure likewise poisons action
and reports recovery-required while preserving the already armed recovery token
for the owning outer callback. The preparer never retains an outcome itself.
This intermediate seam closes the specific cursor-only topology-observation gap
at its own code boundary; it is not the active controller and supplies no
release, runtime, sequence-2, persistent-topology, success-outcome, or trading
authority.

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
sequence-2 issuer or binder, invokes the claimed-release handoff, either pure
topology snapshot, the dormant observation reader, or either same-session fence
binder, the claimed chronology seam, its leased wrapper, or the recovery-
outcome module, or the claimed action-topology fence, executes either projected
start argv, invokes the claim or outcome writer through a supported command, or
publishes the release marker.
There is no complete staged-topology controller, retained-evidence/approval
wiring, topology mutation, sequence-2 runtime mutation, confirmed start
outcome, or graceful-stop operator. The reader's exact in-container probe is
observation-only and cannot publish either release path. `trusted-time-start`
and shutdown remain hard closed.

The next implementation remains a separately reviewed active controller. While
healthy, the now-implemented private one-shot action lease must remain inside
the same callback and continuously open PID-bound issuer/global-launcher-lock
session from fresh topology creation and staging through ordinal 1, claim
preparation and the now-implemented final full live action-time reobservation,
then through the exact marker release, bounded sequence-2 terminal, persistent-
topology qualification, and durable success retention. The fixed 300-second
deadline remains the one deadline for that successful callback; it is never
restarted at release or a later stage, and the callback must not return with
only either unqualified claimed fence.

Poisoning or deadline failure revokes the action token immediately and
irreversibly, but the owning callback and outer flock remain live until owner
unwind. The new exact claim-bound callback-local retention capability permits
only the one pre-release `recovery_required` disposition described above; it
does not restore observation or mutation authority. If retention cannot be
confirmed or the process crashes, the consumed claim remains the durable hard-
closed recovery fact and never authorizes retry. These dormant seams grant no
release, runtime, sequence-2, persistent-topology, or trading authority. The
controller's exact merged revision and images require fresh admission and
separate operational approval before execution.

## Consequences

The runtime now has an explicit pre-mutation barrier, and the dormant claim
writer freezes the required exclusive durability semantics in one global fixed
slot while treating every legacy per-operation claim as consumed authority.
Neither that seam, the import-only handoff, either pure topology snapshot,
either same-session fence, the claimed chronology or action-topology result,
nor its private callback lease connects approval to release or a post-release
qualified topology. A projected Docker argv, caller-supplied inspection or
marker state, structurally valid fence, retained claim, container creation,
lease token, and marker capability therefore still are not authorization or
success. Poisoning
caused by raw issuer interference is fail-closed and does not release the flock
early. A retained `recovery_required` disposition is evidence of a hard-closed
pre-release failure, never success or a retry permit. The already-retained
enrollment evidence remains historical proof; it is never rewritten, deleted,
or used as an implicit start permit.

The new observer can authenticate only an already-existing exact sequence-2
state; it cannot create that state or qualify topology, release, start outcome,
or shutdown.

No sequence 2, persistent topology, `clean_stop`, provider-terminal observer,
watchdog deployment, readiness, alert delivery, new-exposure gate, trading
authority, or Phase 6 exit evidence is created by this ADR.
