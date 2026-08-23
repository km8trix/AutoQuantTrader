# ADR 0099: Approval-bound post-enrollment start and graceful stop

- Status: Accepted (contract, dormant globally fixed claim/barrier, read-only
  sequence-2 observation/binding, import-only claimed-release handoff, pure
  topology snapshots, bounded observation issuer, and pure two-stage same-
  session topology fence plus code-only claimed pre-release chronology and
  callback-scoped lease/deadline, retained recovery-outcome, final claimed
  action-time topology-fence, active-controller admission, code-only effecting
  controller, shared sequence-2 deadline/ready protocol, persistent-topology
  binder, terminal controller outcome, and ADR-0103 v3-only standalone one-shot
  host executor; no live execution)
- Date: 2026-08-08
- Extends: [ADR 0098](0098-canonical-post-enrollment-start-evidence-review.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

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
without stable approval-bound provenance, a single-attempt reservation, a
durable claim, or a qualified outcome.

## Decision

Freeze a distinct post-enrollment start operation. Its exact approval binds:

- one UUIDv4 operation identity;
- the confirmed enrollment operation ID, claim SHA-256, outcome SHA-256, and
  reduced evidence SHA-256;
- the ADR-0098 review-projection SHA-256;
- one later Git revision, stable content-addressed base-image-provenance
  SHA-256, and immutable source and supervisor image IDs, distinct from the
  enrollment launch;
- every sequence-1 intent, receipt, readback, current-anchor, semantic,
  current-host-head, deployment-identity, and remote-namespace digest; and
- the only permitted first successor: exact integer sequence `2` with reason
  `epoch_rotation`.

The approval is stable domain authority for that exact provenance tuple, not a
freshness witness or an attempt record. It may be presented again only after a
confirmed pre-slot failure left the permanent attempt slot absent; it never
survives reservation or reservation ambiguity. All readiness, operational-
control, arming, exposure, new-exposure, broker-action, alert-delivery, re-arm/
resume, paper-trading, and live-trading authority fields remain false. Start
approval is not trading authority, shutdown authority, or permission to create
any successor other than the bound sequence 2.

Before any epoch registration, signing, or provider mutation, the one-shot host
runtime must hold the host's global trusted-time launcher lock and freshly
reauthenticate the complete local SQL head plus a bounded stable full remote
audit. It must prove the exact retained sequence-1 intent and receipt, current
head and semantic digests, all deployment identities, one remote object, the
same stable namespace digest, no pending intent, no unanchored local suffix,
and no higher remote sequence. Fresh observation counts need not equal the
historical upload/idempotent counts; the immutable bytes and terminal state
must equal them.

The host executor must use this staged release protocol:

1. authenticate the stable approval/provenance, hold owner responsibility for
   every staged input, complete reversible daemon/Compose/image diagnostics,
   and issue an independent fresh image witness;
2. under the same launcher flock and choreography lease, prepare an exact-empty
   reviewed create, reserve and revalidate the permanent attempt slot, store the
   mutation flag, and execute only that prepared create; the stopped supervisor
   cannot register an epoch, sign, or contact the provider before an exact
   release marker;
3. authenticate retained enrollment evidence and the proposed launch, perform
   the fresh read-only runtime reauthentication, retire all staged host inputs,
   and retain an owner-only mode-`0600`, `O_EXCL`, fsync-confirmed start claim that
   binds the exact approval and fresh reauthentication digest;
4. revalidate every approval, witness, image, daemon, topology, mount, and retained-
   evidence binding, then publish the one exact release marker;
5. require the runtime to register its epoch and confirm sequence 2 as
   `epoch_rotation`; and
6. authenticate that SQL/remote successor and the still-qualified persistent
   topology before retaining a content-addressed confirmed host outcome.

Compose `running` state is never a confirmed start outcome. A confirmed failure
before permanent attempt-slot reservation cleans owner-held inputs, leaves the
slot absent, and keeps the same stable approval eligible; it does not trigger a
new human approval. Once reservation may have begun, slot state is permanent.
Before claim and release, a post-slot failure must tear down without sequence 2
but still consumes the attempt. Once the claim is retained, any uncertain
release, runtime exit, sequence-2 result, teardown, outcome retention, or lock
release is recovery-required. A missing confirmed outcome must never be retried
as a new start. Recovery needs
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

[ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md)
now implements only the durable evidence prerequisite for that future path.
Controller outcome v2 embeds the complete canonical persistent-topology
locator; historical v1 outcomes remain valid terminal evidence but have no
locator and cannot construct the normal confirmed-start stop target. A separate
canonical stop target and decision freeze exact bindings plus a stop-only replay
domain and decision while every authority and authentication fact remains
false. [ADR 0105](0105-inert-post-enrollment-graceful-stop-operator-attestation.md)
now adds only a separate strict public stop authority identity, canonical
statement/envelope, explicit public verifier, and offline public candidate
workflows. The real authority remains absent, and there is still no signer,
reviewed-Git runtime loader, replay slot, currentness verifier, admission,
outcome writer, effecting CLI, Docker caller, or shutdown effect.
[ADR 0106](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md)
now adds only the strict current-v3 start-attempt loader and an offline binder
that reloads and cross-binds the committed confirmed outcome v2, locator,
attempt slot, and signed start envelope before publishing an inert
content-addressed decision-v1 candidate. It adds no stop signature,
currentness, replay reservation, admission, outcome/recovery, or effect.
[ADR 0107](0107-fail-closed-clean-stop-completion-invariant.md) now additionally
requires the exact current `clean_stop` request to produce its own paired remote
readback and durable receipt before the worker can report clean completion. An
unchanged-head no-candidate result or a receipt recovered for an older intent
is unconfirmed and cannot substitute. This adds no no-record success protocol,
stop outcome, slot, admission, or effect.
[ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md) now preserves
that exact new-record completion as a PID- and identity-sealed process-local
result. It binds the request schedule, sequence, predecessor, current head and
anchor, reconciliation counts, current intent/readback/receipt, and a semantic
digest, then permits one atomic consume by the exact request object. The
background worker exposes an additive exact-result accessor, but main does not
call it and no authenticated live wire handoff or transport,
provider-terminal currentness, durable stop outcome, reservation, admission,
signal, Docker, or teardown surface exists.

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
- an import-only claimed-release handoff whose sole host caller must already hold
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
`/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python`, followed by the
fixed target ID `post-enrollment-release`, with no additional arguments. It
authenticates neither container nor topology identity;
`container_identity_authenticated` and `topology_authenticated` remain false.
The ID remains untrusted until the topology issuer independently revalidates the
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
`phase6d-post-enrollment-topology-observation-reader-v3`. Its exact caller-owned
inert issuer is activated in place, owns one opaque native global launcher-lock
lease, and pins one canonical absolute Docker executable,
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
is revoked before callback return can escape. The C at-fork handler closes the
child's inherited lease descriptor first; the sole Python child callback then
scrubs closure and heap state without native calls or inherited-lock
acquisition.

The callback fixes one absolute 600-second deadline at acquisition on the
topology issuer's identity-sealed, suspend-aware host action clock. Production
uses Linux `CLOCK_BOOTTIME` or macOS `mach_continuous_time` scaled with
`mach_timebase_info`; every other or unavailable platform fails closed, and an
injected clock is test-only. Every checkpoint rejects clock regression and
treats equality with the deadline as expired. Raw Docker reads retain their
two-second deadline; leased Docker
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
monotonic origin at `start + 605 seconds`. It is an absolute outer bound: claim
retention, lease poison, action-deadline expiry, recovery-capability arming, and
retention start never reset it. Equality is expired at both `start + 600
seconds` for every action and `start + 605 seconds` for recovery retention. An
`unbound` or `claim_admitted` recovery capability is revoked by action poison or
the 600-second equality boundary and cannot be armed during the outer interval.

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
issuer has no CLI, worker, controller, provider, SQL, claim writer, release, or
outcome-persistence surface of its own. Its exact one-shot host caller alone may
use the narrow reviewed create/start/pre-claim-teardown state machine.

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

At action poison or the `start + 600 seconds` equality boundary, every Docker,
observation, cursor, release, provider, SQL, and other action authority is
revoked immediately. While the same owning callback and outer flock remain
live, the armed recovery capability is the sole non-action exception. Function
`retain_post_enrollment_start_recovery_required_outcome` may consume it exactly
once, before the unchanged `start + 605 seconds` equality boundary, to retain
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

Contract `phase6d-post-enrollment-start-active-controller-admission-v1`, with
sole status `active_controller_admission_unqualified`, adds the first dormant
active-controller admission boundary without performing an effect. Function
`prepare_post_enrollment_start_active_controller_admission` accepts only the
exact process-sealed claimed action-topology fence and its one-shot private
controller-origin tuple: issuer, active lease, armed recovery capability,
artifact and ignored roots, PID, and thread. It consumes that tuple through
`_consume_claimed_action_fence_controller_choreography`, independently
revalidates the exact action fence and retained claim, and repeatedly requires
the same live lease, named lock, issuer/daemon session, roots, shrinking
deadline, and armed recovery escape through result construction.

Successful consumption removes the full tuple from the action-fence registry
and leaves only a weak reference to the originating issuer as a consumed-origin
tombstone, so a replay still poisons the origin without retaining lease,
recovery, or root authority there. After the remaining checks and exact result
construction succeed, the preparer registers that same exact tuple in a
distinct one-shot future-continuation registry bound to the exact admission
result. Any ordinary or asynchronous failure after origin consumption and
before return unregisters any partially installed admission-result and
continuation state, leaves the action-fence registry's weak tombstone intact,
and poisons the originating action. Neither tuple nor any lease, recovery, root,
PID, thread, or deadline value enters the public payload. Private
`_consume_active_controller_continuation` is called only by the code-only
`run_post_enrollment_start_active_controller` tail, which is reachable only
through the standalone one-shot host orchestrator. The seam is pop-before-
validation and one-shot: an exact-result
attempt replaces the continuation's full origin tuple with an admission-local
weak issuer tombstone across ordinary or asynchronous failure, and makes replay
fail closed and poison the origin without granting an effect. The admission
result is process-local, non-copyable, nonserializable, invalid after fork, and
directly retains only sealed nested evidence.

Preparation authenticates only the exact claimed action fence, live issuer/
lock/daemon session, active callback lease, armed recovery capability,
canonical roots, PID/thread binding, and retained-claim revalidation at this
boundary. Those transient checks are not asserted to survive return: current-
session, freshness, and topology-authentication fields remain false. It
performs no Docker, file mutation, release, SQL, provider, topology, or outcome
action and does not make the prior topology observation current for a later
effect. An input of the wrong action-fence type is rejected. Once an exact-type
action-fence object is presented, a missing, wrong, stale, or replayed origin
tuple and any later claim,
lease, armed-recovery, lock, root, deadline, or result failure are recovery-
required, poison the registered or tombstoned originating action, and leave the
already armed recovery capability to the owning outer callback. Every release,
runtime, sequence-2, persistent-start, topology-qualification, success-outcome,
shutdown, operational-control, readiness, exposure, broker, paper-trading, and
live-trading authority field remains false. The payload and result explicitly
expose `active_controller_authorized=false` and
`controller_execution_authorized=false`; admission is not controller execution.

Contract `phase6d-post-enrollment-start-sequence-two-verifier-v1` replaces a
caller-supplied sequence-2 repository attempt with a process-private exact two-
call verifier. Its pre-effect preparer binds the exact admission, issuer, lease,
recovery capability, roots, PID/thread, retained claim, original action
deadline, database identity, and read-only configuration. Resources are lazy
and closure sealed. Its SQL route permits only deadline-guarded verification
reads; its provider wrapper exposes no upload, and only the public Ed25519
verifier is present, with no signer or private key. The first call must finish
before the original deadline minus 85 seconds and the second before minus eight
seconds. Both use the exact clock object sealed into the topology issuer rather
than independently sampling another host clock domain, and both independently
perform complete SQL replay, a stable bounded two-
object remote audit, and complete SQL replay again. Only identical results and
confirmed cleanup create `verification_transcript_sha256`. Replay,
substitution, cross-process/thread use, lateness, or interruption while origin
material remains closes the verifier and poisons the issuer. Every terminal
zero-, one-, or two-call path erases admission, binding, claim, issuer
reference, lease, recovery capability, deadline, PID/thread, and resources,
retaining only inert status plus binding, configuration, and optional completed-
transcript digest projections. A later replay still rejects but cannot poison
an erased issuer. The pure successor binder still requires the claim's
sequence-1 predecessor and all nine identity digests and remains non-authorizing.

Contract `phase6d-post-enrollment-start-active-controller-v1` now implements
the exact code-only effecting tail. It consumes the admission continuation only
inside the same callback, live lease, PID/thread, issuer/daemon session, named
outer lock, roots, and original 600-second deadline. It performs one fresh
16-read staged-unreleased reobservation, requires the six deadline/release/ready
final and staging names to be absent, and requires at least 260 seconds of
remaining lease budget before the effect. Exact command provenance and the
canonical opening environment projection are sealed into the issuer session.

Immediately before release, the issuer creates a caller-owned post-effect
candidate and atomically transitions the pre-release recovery state into post-
effect controller-outcome retention. A committed transition survives ordinary
or asynchronous interruption and makes the old writer unusable. This irreversible
transition immediately before command spawn is conservatively the
`release_attempted=true` boundary. Even when interruption prevents the spawn
syscall, the disposition is post-effect/attempted and cannot fall back to the
legacy pre-release writer. The in-container
release command publishes canonical owner-only contract
`phase6d-post-enrollment-start-sequence-two-deadline-v1` before publishing the
fixed release marker. That marker binds the release digest and a Linux
`CLOCK_BOOTTIME` deadline exactly 120 seconds after issuance, plus the current
boot identity by digest. PID 1 reads the same deadline before runtime
composition. One process-bound guard requires 50 seconds before durable SQL and
16 seconds before bounded provider I/O, checks afterward, and is retired only
after ready publication. Its initial normal full-audit worker uses the absolute
deadline minus five seconds, checks the at-most-115-second cutoff before every
work selection, and does not enter long-lived supervision until the full-audit
epoch rotation succeeds and
`phase6d-post-enrollment-start-sequence-two-ready-v1` commits.

The read-only in-image
`autoquant-trusted-time-post-enrollment-runtime-state` executable waits only to
that same 120-second deadline and revalidates release, deadline, ready marker,
and deadline openness before returning its closed
`phase6d-post-enrollment-runtime-state-v1` receipt. It exposes the deadline file
only as `sequence_two_deadline_marker_sha256`. The host command timeout is 122
seconds and the pre-effect lease
gate is 260 seconds; later gates require 130, 50, and five seconds before the
next respective phases. The controller then requires two equal successor reads
around one persistent-topology pass containing stable before/after post-release
namespace observations. That pass contains three equal
database/deadline/release/ready/staging-absence barriers, with the third and
final barrier after every other topology read. It binds
`phase6d-post-enrollment-start-persistent-topology-snapshot-v1`, and exclusively
retains current contract
`phase6d-post-enrollment-start-retained-controller-outcome-v2`. V2 embeds the
complete canonical `phase6d-post-enrollment-start-durable-shutdown-locator-v1`
payload and its SHA-256 whenever persistent topology is present. Exact v1
payloads and their v1 slot/commit markers remain loadable as immutable
historical terminal evidence; they are never migrated and expose no locator.

Those repeated marker equalities prove conditional currentness only while each
final marker pathname is governed by a trusted write-once publisher and no
hostile same-UID writer can replace or modify a marker during the sequential
multi-marker probe. This code does not claim an aggregate atomic filesystem
snapshot; it makes several bounded sequential observations. Production
activation remains blocked until admission establishes that
write-once/no-hostile-writer boundary or a future compound native snapshot
transaction replaces the sequence.

Fixed-probe semantic validation is also conditional on explicitly excluded
selection and spawn boundaries. Each producer captures its stdout/stderr sinks
before any filesystem or schema callback; the process-entry stream selection
must therefore already be trusted. The caller captures daemon/environment
primitives before resolver callbacks and binds an exact executable string plus
`Stat9`, but same-inode executable bytes, loader closure, and hostile external
replacement remain admission responsibilities. Topology, active-controller,
and schema-verifier probes still cross the legacy Python runner/Popen boundary,
which reconstructs mutable environment/cwd state and does not establish an immutable aggregate spawn transaction.
Production activation remains blocked
until the admitted native broker/launcher closes that host-spawn boundary; the
current tuple/parser repair does not claim otherwise.

Closure-owned issuance/choreography live-call tokens and the callback-only exact `RLock` runner are audited here solely for opaque-lease retention and close disposition, not as authentication of mutable choreography, checkpoint, retention, recovery, or effect authority. No held lock or opaque-lease authority crosses a function `RETURN`, generator `yield`, or context-manager handoff.

Mutable `ChoreographyRegistration`, `_ChoreographyCheckpoint`, recovery, post-effect, and controller retention checkpoints/outcome state, and the effect-authority graph are a separate production-activation blocker outside this signoff. Every effect remains blocked until their tuple state is hardened and their entire transitive path proves exact `KeyboardInterrupt`/`SystemExit` identity and cleanup. The legacy unenrolled/enrollment Python launch-lock and runner/Popen spawn paths, hostile same-UID writer/path replacement after validation, and executable/tool-byte admission also remain explicit blockers.

The final TEST-only native issuer choreography freeze now covers Checkpoints
A–O and operation tags 1–15. It retains native ownership of the opaque launcher
lease: Python receives no descriptor, `fileno`, or `detach`, and the registered
C at-fork handler closes and scrubs the child's inherited lease before the
Python child callback clears its closure and heap views. The `inert` →
`activating` → `active` → `burned` lifecycle, exact PID/interpreter/thread
and `RLock` binding, closure-owned live-call tokens, choreography checkpoints,
and recovery, post-effect, and controller-retention records are now covered by
the complete TEST matrix. No held lock or opaque authority crosses `RETURN`,
generator `yield`, or a context-manager handoff.

The exact evidence cut pins native source SHA-256
`da2bc638b92b49a4c1c747d02983558d1dbff80fa7c7c64e16bbefa669e051d5`,
final Checkpoint-O contract SHA-256
`fbe300d11a721bff67329394a00a1be7337de96de23ed816a2ec877d2dbca388`,
and owned-test candidate SHA-256
`65be32ea883ceee022d2ba88781a5342190bf98f5b68c51beee9deeedb3b598d`.
Checkpoint O is TEST-only tag 15, `formal_force_revoke`. It accepts only an
exact empty built-in tuple, covers all 13 phases, requires a completely zero
fail-closed origin and `1 <= q <= UINT64_MAX-3`, and admits exact `ACTIVE` or
`BURNED` outer lifecycle state. `REVOKED` is a real revision-advancing
self-edge, not an inert replay.

Normal O publication installs the canonical `REVOKED` State at `q+1`.
Every attached authority becomes `REVOKED` at `q+1`, every attached witness
becomes `CLEARED` at `q+1`, and every State summary and dependency tombstone is
zeroed. A pre-store hard row publishes State and attached-record terminal
revisions at `q+1`; a post-store hard row advances only State to `q+2` while
the already-detached records remain terminal at their actual `q+1` publication.
Every attached non-durable record has exact `prepared_at_revision + 1`
lineage; a prepared controller receipt is at exact current revision `q`, and a
durable controller receipt is the sole exact `prepared_at_revision + 2`
exception. Its immutable historical/current lifecycle relation permits only
`ACTIVE` → `ACTIVE`, `ACTIVE` → `BURNED`, or `BURNED` → `BURNED`; resurrection
from historical `BURNED` to current `ACTIVE` is rejected.

O performs no clock sample, filesystem or path proof, external-barrier action,
or durability reproof. Repairable semantic mismatches reconcile once to the
exact pre-store or post-store hard row and surface as `OSError`; organically
unreachable persistent corruption of captured immutable record or binding
bytes is never restored or rebound, and forced complete/raw confirmation of
that impossible state fail-stops. Exact `KeyboardInterrupt` and `SystemExit`
identity and cleanup precedence remain covered.

On CPython 3.12.13 and 3.13.3, the isolated O behavior matrix passed 541 tests
per minor (1,082 total), and the full plugin-free A–O suite passed 1,993 tests
per minor with only the same two inherited `os.fork()` warnings. Strict TEST
and production builds passed on both minors (the TEST build retained seven
audited inherited warnings; production retained zero), and `_self_test()`
returned `None` on both. The CPython 3.12 ASan+UBSan run passed; leak checking
alone was disabled because Darwin does not support that sanitizer mode.
Production preprocessing, string, and symbol audits found no Checkpoint-O or
tag-15 identifiers, tokens, methods, or exported symbols.

This closes only the guarded TEST choreography matrix; it does not constitute
runtime or production admission. No issuer caller is operationally admitted,
and the guarded TEST-only native surface grants no Docker, spawn, mutation,
retention, release, or effect authority. The reviewed but non-admitted host
allocates and activates explicitly and closes in `try/finally`.
Validation and a later Docker effect are not atomic, and hostile same-UID path
replacement, the legacy Python runner/Popen environment and spawn boundary,
executable/tool/loader-byte admission, remaining process-callsite migration,
containment, immutable image and effective-mount receipts, and root-owned
read-only deployment remain explicit production-activation blockers.

`post_enrollment_start_confirmed` is possible only with the complete fresh pre-
effect digest, release/runtime-state/sequence-2 successor/persistent-topology
evidence, and persistent-topology transcript digest. If both sequence reads and
persistent topology qualify but durable success retention does not,
`success_outcome_unconfirmed` preserves those true facts while overall
qualification and controller success remain false. The fixed reason progression
is `release_outcome_unconfirmed` → `sequence_2_unconfirmed` →
`success_outcome_unconfirmed` → `post_enrollment_start_confirmed`. Sequence
stays unconfirmed until the second equal verifier read after the persistent-
topology pass. After that second read, a final runtime-state command capped at
two seconds must return the exact same receipt and digest as the first; the
controller publishes transcript, successor, and success evidence only after
that equality check. The contract has no separate
`persistent_topology_unconfirmed` terminal reason.

Outcome retention is two-phase. The controller writer and legacy recovery
writer both atomically reserve permanent global slot
`.post-enrollment-start-controller-outcome-slot` with `O_EXCL`; either writer's
partial reservation excludes the other. The controller first makes the slot and
content-addressed outcome durable as public-ineligible `prepared` state. After
the process-private registry reaches `post_effect_confirmed`, the publisher
holds the slot lock exclusively, promotes
`.post-enrollment-start-controller-outcome-commit-staging` to fixed commit
marker `.post-enrollment-start-controller-outcome-committed`, and fsyncs the
directory entry. Public `committed` load and revalidation hold the slot lock in
shared mode, require commit staging absent, and revalidate the exact slot,
prepared artifact, and commit-marker bytes and inode. Commit failure downgrades
the registry to `post_effect_unconfirmed`; asynchronous interruption after the
exact public committed receipt revalidates instead preserves
`post_effect_confirmed`. The legacy recovery writer initializes that exact
shared-slot inode with status `reserved` and holds it under an exclusive lock
through fixed hidden staging
`.post-enrollment-start-recovery-outcome-staging` write and file fsync, final
hard-link, first directory fsync, staging unlink, identity check, second
directory fsync, and final byte readback. Only then does it rewrite and fsync the
same slot as `retained`, fsync the directory, and re-read the exact slot bytes
and inode. Its load and revalidation paths take the slot lock in shared mode,
fsync slot and directory, require exact `retained` status with staging absent,
and bind the final and slot identities; a controller-contract slot cannot
validate a legacy final. A `reserved` or partial slot keeps an ambiguous final
ineligible even if cleanup cannot restore staging. Cleanup attempts final-to-
staging rename, staging-sentinel creation, then final unlink, and verifies
staging-present or final-absent state. A later loader may instead independently
fsync and confirm an exact fully written final whose slot already reached
`retained`. Every incomplete phase blocks concurrent, legacy, or later retry.
Each post-effect ambiguity maps to one progress-sensitive `recovery_required`
outcome; it is terminal and never a retry permit. Failure to confirm retention
remains a distinct hard-closed error. Poisoning still leaves the owning callback
and outer flock live until owner unwind and never restores action authority.

Code-only contract `phase6d-post-enrollment-start-host-orchestrator-v3` now
implements the operator-attested one-shot host execution boundary. Its separate outer field
`orchestrator_status=terminal_outcome_retained` never replaces the nested
controller or legacy terminal `status`. Canonical
owner-only contract `phase6d-post-enrollment-start-execution-approval-v2` binds
the exact domain approval, proposed merged-revision image tuple, and its stable
content-addressed base provenance in one exact nested artifact. ADR 0103 wraps
those canonical bytes in the signed v3 envelope and makes
`load_post_enrollment_operator_attested_execution_approval` the only
execution-facing loader. It authenticates the exact reviewed Git authority,
plain-Ed25519 statement, complete v2 semantics, bytes/inode, and stable
provenance before Docker, issuer, runtime-input, or reversible preflight. The
host requires current `HEAD` to equal the nested v2-approved revision at that
same early boundary. Owner-held staging and reversible daemon, Compose,
runtime-input, and isolated existing-image probes then complete. Only
then does `verify_and_write_existing_image_admission` write an independent
just-in-time witness for the same clean revision, immutable IDs, reviewed-source
digest, and approved provenance.

Under the already-held launcher flock, the choreography lease first prepares
the sequence-1 verifier and `_prepare_reviewed_topology_creation` binds the
staged paths and effect-only Compose projection while confirming the exact
container/network inventory is empty. Contract
`phase6d-post-enrollment-start-execution-attempt-v3` then permanently reserves
`.post-enrollment-start-execution-attempt-slot` with owner-only `O_EXCL`, fsync,
and exact readback. Its first reservation consumes the host-wide execution
opportunity, not the reusable pre-slot approval artifact. Contract
`phase6d-post-enrollment-start-execution-admission-v3` is process sealed and
one-shot: `reserve_post_enrollment_execution_attempt` binds the complete
operator-attested receipt to the independent witness, and consume immediately
revalidates the reviewed authority, envelope, exact nested v2 approval,
provenance, witness, slot bytes/inode, and at least 605 seconds of witness
headroom on the choreography's native suspend-aware clock. The host stores its mutation
flag before `_execute_prepared_reviewed_topology_creation` issues the effect-only
create. Confirmed failure before reservation leaves the slot absent and the
same stable approval reusable; reservation ambiguity is permanent. V1 wrappers
and every unsigned-v2 execution shape are rejected. Exact complete historical
`phase6d-post-enrollment-start-execution-attempt-v2` slot bytes remain
permanently consumed under the unchanged filename; partial or unknown slot
state remains retention-unconfirmed. Admission grants no
release, topology, runtime, outcome, or trading authority by itself. See
[ADR 0103](0103-atomic-operator-attested-post-enrollment-execution-admission.md).

One topology issuer owns the sole launcher flock from owner-held staging and
reversible preflight through the exact-empty prepared-create fence and
reviewed Compose
`create --no-recreate`, complete callback unwind, and exact close, whether the path
confirms teardown, retains a terminal, or ends in fatal manual classification.
The private mutation
state machine accepts no caller-selected argv, environment, or runner. It
performs the reviewed Compose create, authenticates the stopped two-container
topology, starts and qualifies the source first, starts the supervisor second,
and authenticates its consumed-input barrier. Its effect-only Compose bytes
label both services and assign the default attachment a full domain-separated,
issuer-session-derived network name plus the exact issuer-session invocation
label. The exact derived-name collision is checked before create; later
reviewed observations require both the name and label, so wrong-session or
missing-label resources fail closed. The fixed legacy network remains untouched.
Pre-claim teardown authenticates and removes only the sealed container IDs and
exact authenticated network ID, never a name, broad Compose-down targets, or
named volumes. The issuer seals the exact
created observation before returning it, so lost-return ambiguity can recover
only the exact pre-claim teardown. It also handles one bounded network-only
partial-create state: two stable inventory
reads must show the exact derived name and invocation label with zero
containers, after which teardown removes only that network ID and skips
container removal. Created topology truth, its digest, and all four private
staged-input digests are registered as one atomic in-process value.

The effect-only post-enrollment projection injects four private expected
SHA-256 bindings into the supervisor environment, covering the exact database
URL bytes and the three exact head-anchor inputs. The fixed legacy/base Compose
validator requires these variables absent and grants no start authority;
supervisor main requires all four because only the dynamic post-enrollment
topology may start it. Each loader hashes the exact bytes it read and compares
the binding before decode or use. Only after all four comparisons succeed is
the fixed nonsecret consumed-input marker published. A mismatch exits with code
2 before marker, readiness, or claim, while the authenticated current-attempt
exited supervisor remains eligible for exact pre-claim ID-only teardown.
Restoring the path bytes cannot qualify that failed attempt. The private
digests are not exposed in the marker or command output.

A live materialization owner adopts each of the four exact staged-input inode
records before its materializer
returns, so asynchronous CALL-to-STORE interruption cannot orphan an unknown
secret. It later retires only those adopted records; it never sweeps a runtime-
secret directory.

Contract `phase6d-post-enrollment-sequence-one-read-only-reauthentication-v1`
is the sole sequence-1 path. It has a public Ed25519 verifier and read-only SQL
and provider capabilities, with no signer, private signing key, or upload port.
It binds the same issuer, lease, still-`unbound` recovery capability, roots,
PID/thread, and deadline before topology mutation, is invoked only after exact
staged-input retirement, and must finish before the unchanged 260-second
controller reserve. Retirement is descriptor-anchored and restartable across
partial unlink/rmdir progress while interruption still escapes. The fixed
chronology is sequence-1 preparation; exact-empty prepared-create fence;
permanent reservation; consume/revalidation; mutation-flag store; effect-only
prepared create; source-ready; supervisor-consumed; four-input retirement;
staged ordinal 1 and pre-claim fence;
conservative no-teardown marker CALL; sequence-1 verification while recovery
remains `unbound`; binder transition to `claim_admitted` immediately before
claim `O_EXCL`; retained/read-back claim, in-writer binder consumption, and
commit-last `armed` recovery; ordinal-2 chronology; final action
fence; controller admission; read-only sequence-2 verifier; and active
controller. One suspend-aware origin fixes the 600-second action and 605-second
recovery deadlines.

Exact reviewed Compose teardown, with both named volumes preserved, is permitted
only before the conservative marker-call boundary. The host stores its
no-teardown flag before that CALL, so every ordinary or asynchronous failure at
or after the boundary preserves the topology and whatever evidence is already
durable. An exact read-only state query retains legacy recovery only when the
capability is `armed`; unarmed, advanced, ambiguous, or unclassifiable state is
fatal and requires manual review without claiming a terminal. Failure at or
after reservation, including pre-claim teardown, is projected conservatively as
fatal because the permanent attempt slot is consumed or ambiguous. A confirmed
pre-slot failure instead cleans owner-held inputs, leaves the slot absent, and
preserves the same stable approval for a later explicit attempt. The standalone
isolated host CLI uses `allow_abbrev=False` and exposes only
`--operator-attested-approval-artifact` for the canonical v3 envelope and
`--runtime-env-file` for the owner-only runtime environment file. Its sole
public entry is `run_operator_attested_post_enrollment_start_once`; the old
entry and flag are absent. It is not wired into Make, Compose, worker, trader,
ordinary startup, shutdown, readiness, exposure, broker, or trading surfaces.
The effecting function rejects ordinary import calls; only the attested isolated
`__main__` path may invoke it.
The CLI emits only a terminal returned or raised by this exact process-sealed
invocation; an earlier global outcome cannot substitute for a current preflight,
cleanup, close, replay, or asynchronous failure.
After an exact legacy or controller terminal commits, its current-scope receipt
is retained in the live issuer registry. The controller, host callback, and
outer scope durably revalidate and adopt that exact identity across asynchronous
CALL/STORE or CALL/RETURN handoff; they never search globally for a prior
receipt.
The in-image worker and inspection executable remain reachable only after the
private effect boundary. `trusted-time-start` and shutdown remain hard closed;
no release was executed while implementing this ADR. The exact merged revision,
immutable images, and stable provenance require one exact external execution
approval; each attempt separately requires a fresh just-in-time witness and an
explicit operational decision. A confirmed pre-slot retry does not require
repeated human approval.

The ADR-0104 locator, target, and stop decision, ADR-0105 public signature
authentication, and ADR-0106 authenticated historical-chain candidate do not
weaken that closure. They are canonical, sealed, non-authorizing evidence only.
The pure target builder's caller-supplied v3 start slot/envelope digests remain
unqualified outside ADR 0106's supported artifact-derived binder. Even an
ADR-0106 candidate plus a valid stop signature is not current start-chain or
stop-admission evidence, and `durable_shutdown_locator_available` reports only
structural presence. `trusted-time-stop` remains an exit-2 target with no
effecting caller.

[ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md) now
implements the missing ADR-0108/ADR-0109 correlation as a dormant code-only
seam. One exact request is registered before worker selection, bound to the
exact selected work object, issued from the immutable second-consume ADR-0108
projection, and cross-bound once on the host to ADR 0109. It adds no production
caller, authenticated transport, topology lease, lifecycle-v2 advance, durable
outcome, signal, or teardown, so the graceful-stop operation defined here
remains hard closed.

## Consequences

The runtime now has an explicit pre-mutation barrier, and the claim
writer freezes the required exclusive durability semantics in one global fixed
slot while treating every legacy per-operation claim as consumed authority.
Only the exact private active-controller chain can connect those facts to
release and a post-release qualified outcome; a projected Docker argv,
caller-supplied marker, structurally valid fence, retained claim, container,
lease token, admission result, or runtime-state receipt in isolation is still
neither authorization nor success.
Poisoning
caused by raw issuer interference is fail-closed and does not release the flock
early. A retained `recovery_required` disposition is evidence of a hard-closed
pre-release failure, never success or a retry permit. The already-retained
enrollment evidence remains historical proof; it is never rewritten, deleted,
or used as an implicit start permit.

The controller code can create and authenticate exact sequence 2 and retain a
confirmed start only when the complete private choreography is invoked. This
ADR supplies one narrowly supported start-only host invocation but creates no
live start evidence.
ADR 0107 prevents a no-receipt reconciliation or recovered older receipt from
being reported as a completed `clean_stop`. ADR 0108 preserves only the exact
current new-record result inside the worker process and prevents copy, replay,
cross-core scalar-equal substitution, drift, serialization, and post-fork use.
ADR 0109 adds one code-only host reauthentication with no live or effect
consumer except ADR 0111's dormant zero-caller composition: fresh equal SQL
projections bracket a full
authenticated two-pass provider audit, late terminal GET, empty-next check, and
final identity reattestation under one suspend-aware deadline. It is a bounded
point-in-time observation only.

[ADR 0110](0110-dormant-durable-graceful-stop-lifecycle-repository.md) now
freezes the first durable lifecycle primitive without connecting it to an
operation. One fixed immutable ordinal-zero attempt root is also the permanent
global replay slot, and every admitted later stage must be a typed, gap-free,
predecessor-bound immutable record. There is no second slot, per-operation
root, mutable current-state file, generic append, reset, deletion, retry, or
resume surface. The dormant repository has no production caller, so it reserves
no real attempt. It can retain only a non-authorizing `recovery_required`
terminal for the missing live operation-bound supervisor integration. ADR 0111
now supplies dormant unqualified ADR-0108 correlation and one-shot ADR-0109
consumption seams. Positive post-signal and confirmed-success constructors
remain absent or unreachable until authenticated live transport, same-lock
authority/topology admission, and lifecycle-v2 integration are reviewed
together.

These ADRs still supply no exact current stop-operation binding, stable
currentness lease, production reservation, post-signal durable outcome,
effecting shutdown, independent watchdog deployment, readiness, alert
delivery, new-exposure gate, trading authority, or Phase 6 exit evidence.
