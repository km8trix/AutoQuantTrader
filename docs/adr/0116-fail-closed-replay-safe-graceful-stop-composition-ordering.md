# ADR 0116: Fail-closed replay-safe graceful-stop composition ordering

- Status: Accepted as a design-only dependency and choreography freeze; no
  transport, admission, lifecycle-v2 writer, live registry, authority,
  reservation, signal, teardown, outcome, recovery action, or runtime caller is
  implemented or authorized
- Date: 2026-08-25
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0110](0110-dormant-durable-graceful-stop-lifecycle-repository.md),
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md),
  and
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)
- Extended by:
  [ADR 0121](0121-trusted-time-graceful-stop-lifecycle-v2-implementation-resolution.md)

## Context

ADR 0112 closes the historical decision-receipt handoff into ADR 0111, and
ADR 0111 can correlate one exact preselected worker request with one exact
ADR-0108 result and one bounded ADR-0109 host observation. That composition is
deliberately dormant. Its canonical request and result are structural bytes,
not an authenticated channel, current topology evidence, durable stop progress,
or effect authority. ADR 0110 v1 deliberately ends at ordinal one and cannot
retain a bridge result, pre-CALL intent, authenticated post-CALL result, or
confirmed-success outcome.

ADR 0111's request, result, and host binder are also specifically bound to the
ADR-0110 v1 attempt/progress receipts. They cannot be the live wire or host
binding for a lifecycle-v2 path that must never construct or consume those v1
receipts. ADR 0111 therefore supplies reviewed correlation invariants only; its
v1 contract strings, codecs, decoded objects, attempt/progress inputs, process
seal, and host composite remain dormant historical design inputs, not values
that a v2 implementation may wrap, translate, or reinterpret.

Implementing only the missing host-to-supervisor transport would create a
dangerous partial milestone. A correctly authenticated request could reach the
supervisor while the host still lacked same-lock current admission, a lifecycle
able to classify a lost return, fork-safe live registries, exact teardown, or a
durable terminal outcome. Conversely, reserving the permanent stop slot or
adding post-signal records before the complete ambiguity protocol exists would
consume or strand the only stop attempt without a reviewed recovery invariant.

This ADR therefore freezes the complete fail-closed composition order before
any one live component may be activated. It is a design decision only. It adds
no artifact, key, endpoint, schema, code path, command, or effect.

## Decision

### Treat the five gates as one non-separable activation boundary

Future implementation and review must close these gates in this dependency
order:

1. authenticated, bounded, replay-safe host-to-supervisor request/result
   transport for a separately versioned lifecycle-v2-compatible wire family,
   with exact endpoint origin, deadline, and failure semantics and no ADR-0111
   v1 payload or host binding;
2. one same-lock admission that freshly authenticates current topology, current
   trusted head, installed stop authority and signed stop operation, and the
   exact operation before any reservation or effect;
3. a separately versioned lifecycle-v2 repository and compatible
   request/result/host-binding family that consume that exact admission and
   durably retain every pre-CALL intent, separately authenticated post-CALL
   result, confirmed-success terminal, and recovery-required ambiguity without
   constructing, consuming, rewriting, or reinterpreting ADR-0110/0111 v1
   state;
4. origin-PID, exact-thread, and at-fork invalidation for every transport,
   admission, lifecycle, and effect registry, including inherited descriptor and
   lock cleanup before any such registry may be constructed in a process that
   can fork; and
5. only after gates one through four are implemented, independently reviewed,
   and composed, retain the structural clean-stop wire result; freshly
   reauthenticate and cross-bind it on the host; then execute exact
   supervisor-first stop, source stop, ID-bound container/network teardown,
   named-volume preservation proof, a distinct post-teardown terminal
   reauthentication, and durable terminal outcome.

This is dependency order, not permission to activate gates independently.
Gate four must be built into gates one through three before their first live
registry construction even though its cross-cutting design is reviewed after
their state and ownership surfaces are known. No transport-only,
admission-only, or lifecycle-only production milestone is valid. The complete
composition must remain unreachable until all five gates have one reviewed
integration and fault proof. This preserves ADRs 0111 and 0112's accepted
transport → same-lock admission → lifecycle-v2 dependency order; ADR 0116 does
not supersede or silently reorder it. Preserving that order does not preserve
their v1 payloads as live inputs.

### Require authenticated, bounded, replay-safe transport

The future transport must carry only canonical bytes from a separately
versioned lifecycle-v2-compatible request/result contract family inside a
separately authenticated envelope. The v2 family must preserve ADR 0111's
structural invariants—request registration before worker selection, exact
worker/core/thread association, immutable terminal-result snapshot, one-shot
issue/take, and structural/unqualified wire result—but it must bind a v2 root
and v2 progress only. It must not call, import, construct, decode, consume, or
reinterpret ADR-0110 v1 attempt/progress receipts or ADR-0111 v1
request/result codecs, objects, process seal, host binder, or composite. In
particular, wrapping canonical v1 bytes in a v2-authenticated outer envelope is
not a v2 contract.

The envelope must bind the stop operation, permanent attempt-root identity,
lifecycle-v2 transcript identity, admitted topology and trusted-head
identities, exact supervisor-container identity, request/result direction,
endpoint role, protocol version, one-use message identity, and an explicit
deadline context. ADR 0121 defines that transport-time transcript identity as
`lifecycle_dispatch_prefix_sha256`: a domain-separated digest of the exact
stable ordinal-zero root and ordinal-one request-intent artifacts, their stages,
ordinals, and predecessor relation. Every later transcript must begin with those
same two entries. This deterministic prefix avoids hashing a future mutable
transcript while preventing a request from moving across lifecycle lineages.
Ordinal one binds ADR 0121's exact pre-dispatch request-basis digest; only after
its stable readback does the final request add the intent and prefix digests. A
request identity cannot be reused for another operation, topology, result,
process epoch, transcript prefix, or direction.

Both endpoints must authenticate the peer and the exact origin of each message;
possession of canonical bytes, a filesystem path, a process ID, stdout, a
container label, or access to a local socket is insufficient. Frames and every
nested value must have fixed size, count, and depth limits. Decoding and schema
validation occur only after the bounded authenticated frame is received, and
canonical decoding never promotes transport or origin authentication by itself.

This ADR historically deferred exact cryptographic identities, key custody and
rotation, endpoint type and permissions, message counters, boot/process epochs,
suspend-aware clock source, and numeric cutoffs. ADR 0121 now freezes those
values and their schemas. They are no longer implementation choices: equality
with an authorization cutoff is expired, clock or counter regression rejects,
both directions authenticate independently, and duplicate, delayed, reordered,
reflected, cross-operation, cross-topology, cross-boot, cross-prefix, and cross-
direction messages are terminal failures for that attempt. Implementation,
provisioning, qualification, and activation evidence remain absent.

Every version boundary is fail-closed. The future v2 decoder, builder, and host
binder must reject ADR-0111 v1 contract strings, canonical v1 wire bytes,
decoded v1 request/result objects, ADR-0110 v1 attempt/progress receipts or
digests, the v1 host composite/process seal, caller-adapted scalar or digest
projections of any of them, and any object graph or artifact set that mixes v1
and v2 state. Existing v1 decoders must continue rejecting future or v2
contracts. No common decoder may guess a version from shape, fall back across
versions, or normalize one version into the other.

Transport qualification never authorizes dispatch by itself. No operation
message may be dispatched before gate three has consumed the exact same-lock
admission and durably reserved the permanent lifecycle root. Before that
reservation, any transport preflight failure leaves all effects disabled and
requires a fresh later admission. Once reservation or an intent STORE may have
begun, a missing, late, duplicate, unauthenticated, or unretained result is
recovery-required and never automatic retry evidence.

### Admit current evidence under one continuously held lock

One future host controller must acquire the exact global trusted-time launcher
lock and keep it continuously held from current-evidence admission through
all success-relevant owner cleanup and the fixed terminal-outcome commit. ADR
0121 requires every success-relevant zeroize/unlink/unmount receipt and the
final five-second/600-second precommit authorization check before that
confirmed-success commit; the single fixed-marker protocol is the only work
after the check. Neither cutoff claims durable marker completion, and a
postpublication clock read cannot reclassify it. A precommit cleanup failure
permits only recovery-required and cannot leave success committed.
After the ordinal-23 confirmed-success fixed commit, only invalidation of an already-empty non-authoritative
registry and close of the lease descriptor remain. That disposal is outside
the lifecycle and whole-operation authorization cutoff, owns no secret, effect,
observation, or outcome candidate, cannot invalidate or reclassify the commit,
and is guaranteed to release the flock on kernel process exit. Under that same
lock, before
reservation or transport dispatch, it must freshly:

- authenticate the exact installed, reviewed-Git stop authority and exact
  signed stop envelope without accepting a caller-supplied authority digest;
- reauthenticate the ADR-0112 historical decision receipt through a separately
  reviewed lifecycle-v2-compatible historical-receipt handoff, and bind the
  exact v2 operation/request inputs without constructing or consuming the
  current ADR-0112-to-ADR-0111 v1 handoff;
- observe and authenticate the current topology, exact container/network and
  named-volume identities, durable shutdown locator, and live topology lease;
- authenticate the current trusted head and prove it is the exact admitted
  predecessor for this `clean_stop` operation; and
- construct one exact, process/thread-bound, one-shot operation admission while
  every binding remains unchanged. The admission itself reserves nothing and
  authorizes no transport dispatch or effect.

The admission must bind one immutable snapshot of those facts into the
transport request and the exact lifecycle-v2 reservation input. Gate three must
consume that one-shot admission and durably reserve the permanent root without
releasing the lock or resampling caller-selected facts; only the resulting root
may bind every later intent/result. A current boolean, previously loaded object,
historical topology receipt, process-local seal, or equality of caller-supplied
digests is not admission. Lock loss, owner/thread/PID substitution, evidence
drift, deadline expiry, or inability to prove exact root absence before
reservation begins closes the operation. After reservation may have begun, the
same conditions are recovery-required.

The lock is serialization, not authority. It cannot replace authenticated
topology, trusted-head, stop-authority, operation, transport, or lifecycle
evidence. ADR 0121 fixes a five-second native launcher-lock acquisition, one
opaque continuously held host lease, no second repository flock, a supervisor
that never acquires the host flock, and an exact host/native-owner/repository/
process-local-mutex order. The implementation must prove owner-death handling
and every lock-order/fault vector without permitting a deadlock-dependent
success path.

ADR 0112's current private consumed-snapshot handoff is bound to ADR 0111's v1
bridge identity and is not a v2 input. This ADR historically left two possible
handoffs. ADR 0121 chooses the additive separately versioned private ADR-0112
consumed-snapshot seam bound directly to the v2 bridge identity while leaving
every existing v1 meaning unchanged; an independent duplicate v2 loader is not
the selected design. The new seam may not pass a v1 lifecycle receipt, bridge
request/result, host composite, process seal, or adapted projection into the v2
object graph. Its implementation and import/callgraph proof remain blocked.

### Introduce lifecycle v2 and compatible correlation without changing v1 history

ADR-0110 v1 remains immutable and terminal at ordinal one. Existing v1 bytes,
filenames, digests, meanings, loaders, and recovery-only outcome cannot be
rewritten, migrated, extended in place, or interpreted as v2 progress. An exact
v1 root or any ambiguous/unknown root state permanently denies a normal v2
attempt and requires separately reviewed recovery. V2 must use a new contract
version while preserving the single global replay domain and the same fixed
permanent attempt-slot meaning; it must not create a second replay slot or a
per-operation root. ADR 0121 freezes the exact v2 filenames, stage names, byte
bounds, signed-wire artifacts, transcript identity, and publication protocols;
implementation may not select alternatives without a successor ADR.

The lifecycle-v2 request, result, worker association, historical-receipt
handoff, pre-effect host binder, and post-teardown terminal binder must form one
separately versioned correlation family. The family may reproduce ADR 0111's
accepted safety properties, but it cannot reuse its v1 types or bytes and cannot
use a v1 root as normal-path evidence. An exact existing v1 root blocks normal
v2 activation; an unknown or mixed-version root/prefix is recovery-required.

While the gate-two global lock and one-shot admission remain live, the first v2
transition must consume that exact admission and atomically reserve and
revalidate the permanent root. The root and every successor are immutable,
content-addressed, gap-free, typed, root-bound, predecessor-bound, and durably
revalidated before exposure. There is no generic append, caller-selected stage,
rewrite, delete, reset, rollback, retry, or resume API. Unknown, future,
partial, conflicting, duplicate, skipped, or unstable entries fail closed
without exposing a trusted prefix.

Every potentially effecting external call has a dedicated pair of transitions:

1. append and durably revalidate the exact pre-CALL intent;
2. perform at most that one exact call; and
3. append and durably revalidate its separately authenticated post-CALL result
   before constructing the next intent.

The intent binds the operation, admitted evidence, exact target identity,
effect kind, exact immutable arguments, deadline, and predecessor. The result
binds the same values plus authenticated responder/origin identity, disposition,
returned evidence, and the intent digest. A result cannot be synthesized from
process exit, absence, a boolean, generic `status=stopped`, decoded ADR-0111 v1
bytes or objects, caller-supplied output, or a later observation.

The transport-authenticated v2 wire result remains structural and terminally
unqualified. After retaining it and before any supervisor-container,
source-container, container-removal, or network-removal effect, v2 must retain a
fresh ADR-0109 host SQL/provider reauthentication cross-bound through the
separately versioned v2 host-binding seam to that exact v2
operation/request/result/root. A distinct fresh post-teardown terminal
reauthentication, bound through a separate v2 terminal seam, is a later
required record and cannot reuse or infer truth from the consumed pre-effect
observation.
The durable pre-effect record must be constructed through a private lifecycle
integration from the consumed composite's exact authenticated primitive
projection. Serializing the process-local composite or seal, or accepting a
caller-supplied digest, cannot satisfy that binding.

V2 has exactly two terminal classifications: one durable confirmed-success
outcome after the entire ordered protocol, or one durable recovery-required
outcome for every ambiguity or failure after reservation may have begun.
Recovery-required is evidence, not recovery authority. This ADR historically
left recovery disposition unresolved. ADR 0121 selects classification without
effect continuation: a restarted recovery profile may retain the deterministic
recovery-required outcome for one known prefix or revalidate/finalize the one
already-created exact outcome candidate whose fixed commit alone is uncertain,
but it may never create a new success candidate, dispatch transport, continue,
retry, replay, compensate, or reach Docker. The fixed classifier implementation,
credential provisioning, operator admission, and recovery drills remain
blocked.

### Invalidate inherited state before any live registry use

Every future live registry and owned descriptor must bind the origin PID,
interpreter, exact `threading.Thread` object, operation, and lifecycle root.
Every public or private entrypoint, including cleanup and weak-reference paths,
must check the origin PID before acquiring a registry lock or dereferencing an
inherited object. Integer thread identifiers, scalar equality, copied tokens,
and serialized registry entries are insufficient.

Fork handling must close or invalidate inherited transport endpoints,
descriptors, leases, and filesystem locks in the child before Python registry
state can be used. Python-level child cleanup must replace locks and scrub
registries without acquiring inherited mutexes or invoking an unsafe inherited
native owner. The parent remains bound to its original state; the child gains
no continuation, cleanup, outcome, or recovery authority. Process launch while
an effect authority or lifecycle lock is live is forbidden unless the reviewed
primitive proves the required close-before-registry ordering.

ADR 0121 selects a fixed native pre-Python owner table, `pthread_atfork` child
invalidation, `MADV_WIPEONFORK` key pages, post-native Python registry reset,
and a no-process-creation live state. Implementing and qualifying that mechanism
against the admitted interpreter/platform matrix remain external blockers. PID
checks added after a registry lock, best-effort `atexit` cleanup, or a Python-
only callback that first touches inherited locked state cannot satisfy this
gate.

### Freeze the later effect choreography

Only the future admitted controller may execute the following order while the
same host lock, operation, topology binding, lifecycle lineage, PID/thread, and
deadline context remain valid:

1. durably retain the exact clean-stop-checkpoint request intent, dispatch the
   authenticated lifecycle-v2-compatible operation-bound `clean_stop` request,
   receive the exact transport-authenticated v2 wire result, publish the
   complete canonical signed envelope bytes—including payload and signature—as
   an immutable content-addressed artifact, and durably retain typed evidence
   that binds its absolute admitted path, artifact name, full-envelope/payload/signature digests,
   schema, key, channel, root-plus-intent lifecycle dispatch prefix, counter,
   deadline, and publication receipt;
   transport authentication does not qualify its terminal meaning;
2. issue a fresh ADR-0109 host SQL/provider reauthentication, consume and
   cross-bind it through the exact v2 host-binding seam to the same v2
   operation/request/result/root, and durably bind that pre-effect composite
   before any supervisor-container, source-container, container-removal, or
   network-removal effect;
3. durably retain the exact supervisor-container-stop intent, stop only the
   admitted supervisor-container identity, and durably retain its separately
   authenticated result;
4. durably retain the exact source-container-stop intent, stop only the admitted
   source-container identity, and durably retain its separately authenticated
   result;
5. retain dedicated intents and separately authenticated results while removing
   only the exact admitted supervisor-container ID, then the exact admitted
   source-container ID, and then the exact admitted project-network ID;
6. prove that both exact named-volume identities from admission still exist,
   are unchanged, and were never removal targets; `down --volumes`, broad
   Compose teardown, name-only deletion, and concurrent teardown are forbidden;
7. after the exact container/network absence and volume-preservation proof,
   issue a second, distinct bounded ADR-0109 SQL/provider terminal
   reauthentication and durably bind it to the exact operation, v2 transcript,
   expected `CLEAN_STOP` head, pre-effect cross-binding, and provider identity;
   and
8. complete and durably prove every success-relevant transport/native-owner/
   secret-mount cleanup, publish the final transcript and exact outcome
   candidate, close its success-relevant handles, prove the registry empty, and
   perform the last equality-expired precommit authorization check against both
   the five-second commit-publication and 600-second whole-operation cutoffs.
   Only the one fixed-marker protocol follows that check; neither cutoff claims
   durable marker completion, and no postpublication clock read may reclassify
   a stable commit. Confirmed success requires every prior result plus
   both the pre-effect cross-binding and distinct post-teardown terminal
   reauthentication to be durably revalidated. Every other precommit post-
   reservation disposition is recovery-required or commit-unconfirmed. Empty registry invalidation
   and lease-FD close after that confirmed-success commit are non-authoritative disposal, not a
   ninth lifecycle step or cleanup result.

The clean-stop checkpoint transaction in steps one and two is a prerequisite
to the supervisor-container stop effect in step three. The v2 wire result is
structural and unqualified until the fresh pre-effect ADR-0109 observation is
consumed and cross-bound through the v2 host-binding seam; no
supervisor/source/container/network effect may precede that durable binding. A
signal-delivery return or container exit alone is not completion. The source
never stops first, and supervisor and source stops are not parallelized. The
post-teardown terminal reauthentication is a distinct observation intentionally
issued only after exact teardown and volume-preservation proof; the pre-effect
ADR-0109 observation cannot be reused as the final outcome proof.

ADR 0121 resolves Docker evidence as canonical objects, not generic status.
Admission performs only the fixed six-read sequence `/info`, supervisor full-ID
inspect, source full-ID inspect, project-network full-ID inspect, command-socket
volume inspect, and state-volume inspect. Its ordered request, complete
connection-identity, exchange, and method-trace object lists plus parallel
digests are hashed into the admission/root. Every later call uses one fresh connection whose exact socket
mount/path/device/inode, peer credential and daemon process, local socket
device/inode/`SO_COOKIE`, fixed connection ordinal, and capture/revalidation
times are domain-hashed without treating a raw FD number as identity. Closed
container-stop, container-remove, network-remove, and volume-preservation result
objects embed the exact primary/post-inspect exchanges and connection objects,
complete trace-entry objects and parallel request/connection/exchange/trace
digests, HTTP/framing/body/projection digests, timestamps, and outcome. The
gap-free Docker connection/method order is exactly `0..17`; no implicit read,
reorder, retry, or digest-only result can qualify.

### Freeze conceptual states without inventing a wire schema

The future v2 state machine must distinguish at least these semantic states:

- no reserved attempt and no effect authority;
- one durably reserved v2 attempt;
- exact pre-CALL intent durable for each ordered effect;
- exact authenticated post-CALL result durable for that intent;
- fresh pre-effect ADR-0109 observation cross-bound to the exact structural
  lifecycle-v2-compatible operation/request/result/root;
- exact supervisor-container and source-container stop results durable;
- topology absent with both named volumes preserved;
- distinct post-teardown terminal reauthentication durable;
- confirmed-success outcome durably committed; and
- recovery-required outcome durably committed or retention unconfirmed.

Only an exact authenticated post-CALL result may advance from one effect to the
next. The structural clean-stop result additionally requires the durable fresh
pre-effect ADR-0109 cross-binding before any stop/teardown effect. Only the
distinct post-teardown terminal reauthentication may advance to confirmed
success. A missing later record proves nothing about whether an earlier call
occurred. These names are semantic requirements, not reserved contract strings;
ADR 0121 freezes their exact v2 status values and encodings, which the still-
absent implementation must follow.

### Classify crash and STORE/CALL ambiguity conservatively

| Last provable boundary | Required classification | Retry or advance rule |
|---|---|---|
| No root creation began and no effect authority was issued | No attempt is proven; all effects remain closed | A later attempt requires complete fresh admission; transport state is not reusable |
| Exact v1 root or prefix is observed before v2 reservation | Normal v2 is permanently denied because the permanent slot is consumed | Preserve exact v1 evidence; only a separately reviewed recovery path may act |
| A v1 input or mixed v1/v2 object graph is rejected before any v2 STORE begins | This operation is closed; no v2 attempt is proven unless durable artifact state is itself mixed or untrusted | Never wrap, adapt, fall back, or reuse transport state; a later attempt requires complete fresh admission and exact root absence |
| Root or intent STORE may have begun, but exact durability cannot be revalidated | Recovery required; retention may be unconfirmed | Never retry, recreate, clean up, or infer absence |
| A cross-version value or artifact is detected after v2 reservation may have begun | Recovery required; no later intent or effect is admitted | Preserve the complete prefix; never substitute a same-looking value from either version |
| Exact pre-CALL intent is durable, but control is lost before or during CALL | Recovery required because call occurrence or completion is not durably known | Never repeat the call automatically |
| CALL returned, but authenticated result was absent, invalid, late, or its STORE is ambiguous | Recovery required | A return value, process exit, later absence, or observation cannot manufacture the missing result |
| Structural v2 wire result is durable, but fresh pre-effect ADR-0109 reauthentication/cross-binding is absent, failed, or ambiguously stored | Recovery required; no stop or teardown effect is admitted | Never treat transport authentication as terminal qualification or use a prior observation |
| Fresh pre-effect cross-binding is durable, but control is lost before supervisor-container-stop intent | The checkpoint result is cross-bound, but no later effect is authorized | Preserve/authenticate the prefix under ADR 0121's still-unimplemented classifier; never continue an effect |
| Exact authenticated result is durable, but the process stops before the next intent | The previous call is confirmed, but continuation is forbidden | Preserve/authenticate the prefix under ADR 0121's still-unimplemented classifier; never continue an effect |
| Teardown result is durable, but volume preservation or the distinct post-teardown terminal reauthentication is absent/failed | Recovery required; success is false | Preserve volumes and evidence; do not replay teardown or reuse the pre-effect observation |
| Confirmed-success outcome publication began but commit cannot be revalidated | Outcome retention unconfirmed and recovery required | Revalidate the exact candidate/commit only; never publish a second outcome |
| Exact confirmed-success outcome is durably committed and revalidated | Terminal success for that one operation | No retry, resume, re-arm, or further stop effect |

Ordinary exceptions, asynchronous exceptions, process death, host restart,
deadline expiry, lock loss, transport truncation, and storage failure follow the
same table. Cleanup may close caller-owned descriptors and release locks; it may
not erase or rewrite any possibly durable lifecycle or outcome artifact.

### Preserve recovery invariants

- One operation has one permanent replay root, one gap-free transcript, and one
  terminal publication domain. A recovery-required and confirmed-success
  outcome cannot both qualify.
- Any state after reservation that is not exact durable confirmed success is
  hard closed. Recovery evidence grants no signal, retry, teardown, re-arm,
  exposure, broker, paper, or live-trading authority.
- The structural v2 result grants no supervisor/source/container/network
  effect. The fresh pre-effect ADR-0109 cross-binding through the v2 host seam
  must be durable first, and it can never substitute for the distinct
  post-teardown terminal observation.
- Missing artifacts, missing containers, an empty network inventory, preserved
  volumes, current SQL, provider state, or a generic stopped process never
  proves that a prior call did or did not occur.
- ADR 0121 defines the classification-only recovery authority, exact allowed
  transitions, ambiguity handling, and exact-candidate finalization; its
  executor, credentials, admission, and operational approval remain absent.
  Recovery never continues an effect.
- Existing v1 roots/prefixes and every possibly durable v2 artifact are retained
  exactly. Recovery does not migrate, truncate, unlink, replace, or reinterpret
  them.
- Named volumes and external signed/SQL/provider evidence remain preserved
  through every unconfirmed path. Shutdown success never authorizes deletion or
  application resume.

### Keep all runtime and authority surfaces absent

This ADR changes documentation only. It adds no Python, native, test, SQL,
migration, schema, key, authority manifest, runtime caller, socket, process,
thread, worker, registry, lock, CLI, Make target, Docker/Compose wiring, signal,
provider request, teardown, reservation, lifecycle artifact, outcome, or
recovery action. It does not install the stop authority or inspect any external
state.

`make trusted-time-stop` remains the exact no-prerequisite two-line hard-close.
It prints the exact message
`trusted-time-stop is approval-blocked: no effecting approved shutdown operator is implemented`
to standard error and exits 2 without invoking Python or Docker. Every
currentness, transport, origin, lifecycle-v2, admission,
reservation, signal, teardown, outcome, recovery-action, operational-control,
readiness, exposure, broker, paper-trading, and live-trading fact remains false.

## Threat model

The future composition must fail closed against:

- replayed, reflected, duplicated, reordered, delayed, truncated, oversized,
  cross-direction, cross-operation, cross-topology, cross-boot, or
  cross-environment transport messages;
- a local same-UID process, replaced socket, inherited descriptor, hostile
  stdout/stderr, mutable environment, path replacement, process injection, or
  container-label spoofing attempting to impersonate either endpoint;
- canonical but unauthenticated bytes, ADR-0111 v1 bytes or decoded objects
  offered to a v2 boundary, scalar-equal heap objects, copied tokens,
  caller-supplied digests, and stale process-local seals;
- cross-version confusion, downgrade, fallback, or adaptation that wraps v1
  request/result bytes, receipts, host composites, or scalar/digest projections
  in a v2 envelope or object graph;
- a transport-authenticated but structurally unqualified v2 result being
  treated as permission to stop a container, and a pre-effect ADR-0109
  observation being replayed as post-teardown terminal evidence;
- a forked child, wrong thread, PID reuse, inherited mutex or flock, dead owner,
  and asynchronous interruption at every validation, CALL, STORE, commit, and
  return boundary;
- stale or substituted topology, trusted-head, stop-authority, operator,
  operation, locator, container, network, or named-volume evidence;
- partial, reordered, rewritten, missing, duplicated, unknown, or future
  lifecycle/outcome artifacts and same-content inode replacement;
- a successful external effect followed by a lost return or unconfirmed STORE,
  including signal, stop, removal, volume proof, terminal reauthentication, and
  outcome publication; and
- attempts to infer success, safe retry, or authority from absence, process
  exit, HTTP/process status, provider eventual state, or a prior observation.

Administrative compromise of the host, kernel, container runtime, provider,
database, external signer, selected cryptographic implementation, or admitted
deployment root remains outside what repository-local evidence alone can
eliminate. The implementation must name and bind those trusted inputs rather
than implying that this ADR authenticates them.

## ADR 0121 design resolution and remaining activation blockers

This ADR originally froze sequencing while deliberately leaving the security-
sensitive mechanisms open. ADR 0121 now resolves the transport/cryptography/
endpoint/key/counter/epoch design, `CLOCK_BOOTTIME` authorization cutoffs,
same-lock admission and lock order, lifecycle-v2 contracts/names/bounds/stages,
root-plus-intent transcript binding, signed-wire retention, ADR-0112 handoff,
fork model, exact Docker reads/effects/results, both reauthentication bindings,
terminal cleanup, and classification-only recovery with exact-candidate
finalization. Those are historical choices resolved by ADR 0121, not options an
implementer may silently reopen. A deviation requires a successor ADR.

The stop path nevertheless remains closed because these activation blockers are
unimplemented or unprovisioned:

- the independent v2 codecs, repository, transcript-prefix derivation, native
  transport/key owners, same-lock admission, fork guard, Docker client,
  reauthentication binders, cleanup proofs, and recovery classifier, plus their
  import/callgraph and fault-injection evidence;
- the exact reviewed stop authority, manifest/selection chain, TPM-bound role
  credentials, tmpfs/socket projections, fixed launchers, executables, images,
  sanitized environment, read-only/noexec mounts, and supported Linux/CPython
  qualification receipts;
- the admitted topology, Docker daemon/socket, immutable IDs, provider/database
  read-only principals, currentness bounds, and every exact authority identity
  required by the design;
- integrated five-gate evidence for deadline authorization, same-lock ownership,
  fork/process loss, every STORE/CALL ambiguity, ID-bound teardown, volume
  preservation, pre/post reauthentication, terminal cleanup, outcome commit,
  exact-candidate recovery, and non-reachability of every fallback/effect; and
- separately approved operator/recovery admission, deployment and rollback
  procedure, drills, branch protection, and production activation review.

Until every blocker has its own evidence and review, all five gates remain
unimplemented as one activation boundary and the entire stop path remains
closed.

## Acceptance evidence

Acceptance of this ADR requires only documentation evidence:

- this ADR is indexed and the architecture, implementation plan, and runbook
  describe the same five-gate dependency order and exact effect order;
- the diff contains documentation only, no migration or source/integrity-pin
  change, and no production or test caller;
- Markdown links and repository documentation hygiene pass; and
- the unchanged `trusted-time-stop` recipe still prints the exact approved
  message and exits 2 with no prerequisite or effect.

A later implementation cannot claim this ADR satisfied until review retains:

- canonical v2 request/result/host-binding and authenticated-envelope test
  vectors, including exact root-plus-intent dispatch-prefix derivation and every
  later transcript's first-two-entry equality, plus tamper, origin, replay,
  reflection, duplicate, ordering, size, five-second/600-second prepublication-
  authorization equality, postpublication non-reclassification, cross-
  operation, cross-topology, and cross-boot failures;
- direct v1↔v2 negative vectors—v1-to-v2 and v2-to-v1—proving that each
  decoder, builder, binder, and loader rejects the other version's contract
  strings, bytes, decoded objects, receipts, digests, roots, prefixes, process
  seals, host composites, and caller-adapted projections; mixed-version
  directories and object graphs must fail closed rather than select a trusted
  prefix;
- an architecture/import guard proving that the v2 implementation cannot
  import or reach ADR-0110 v1 lifecycle loaders or ADR-0111 v1 codecs, builders,
  host binder, or composite, plus evidence that no v1 bytes are wrapped inside
  a v2 transport envelope;
- deterministic crash and asynchronous fault injection at every intent STORE,
  CALL, result STORE, pre-effect reauthentication/cross-binding STORE,
  post-teardown terminal-reauthentication STORE, outcome staging/commit, and
  return boundary, demonstrating the ambiguity table and zero automatic
  replays;
- concurrent, wrong-thread, wrong-process, PID-reuse, fork-child, inherited-lock,
  owner-death, and cleanup-precedence tests;
- an exact trace proving the global lock spans fresh four-way admission,
  lifecycle-v2 reservation, clean-stop request/result, fresh pre-effect
  ADR-0109 cross-binding, every stop/teardown effect, distinct post-teardown
  terminal reauthentication, transport and terminal cleanup, final transcript,
  and the fixed outcome commit without a state-changing gap, plus a separately
  classified postcommit trace proving empty-registry invalidation and lease-FD
  close cannot invoke lifecycle, recovery, outcome, effect, or deadline code;
- ID-bound fake-driver and isolated integration evidence for the structural
  clean-stop result, fresh pre-effect cross-binding, supervisor-container stop,
  source-container stop, per-container/network teardown, both unchanged named
  volumes, distinct post-teardown terminal reauthentication, and exclusive
  terminal outcome;
- proof that v1 artifacts remain byte-for-byte immutable and terminal, v2 uses
  no second replay root, and exact v1, unknown, partial, and cross-version state
  blocks normal v2 and fails closed;
  and
- separately approved deployment, key, executable, image, mount, provider,
  database, and recovery evidence before any operator surface is exposed.

## Consequences

The remaining graceful-stop work is now one ordered safety-complete program,
not a transport feature followed by unspecified cleanup. Review can proceed in
bounded prerequisite slices, but none may be wired live until the complete
composition passes its integrated ambiguity and effect proof.

The cost is deliberate: the first operational graceful stop remains blocked by
unimplemented and unprovisioned transport, admission, lifecycle, fork,
deployment, both reauthentication boundaries, and recovery components and
evidence, even though ADR 0121 has resolved their design choices. A partial
implementation cannot be marketed as progress toward an operator command by
exposing a request channel or reserving the permanent slot.

No current runtime behavior changes. The real lifecycle root remains absent,
the stop authority remains absent, no external state is observed or mutated,
and `trusted-time-stop` continues to fail closed with exit 2.

## Rejected alternatives

- **Implement authenticated transport as the next live milestone.** A request
  can cross the effect boundary without durable ambiguity handling, current
  admission, fork safety, or a terminal outcome. Transport may be developed and
  tested only as an unreachable prerequisite.
- **Reuse ADR-0111 v1 request/result bytes or host binding in lifecycle v2.**
  Those contracts require ADR-0110 v1 attempt/progress state. Constructing,
  consuming, decoding, or reinterpreting that state would contradict the v2
  lifecycle boundary.
- **Wrap or adapt v1 state behind a v2 envelope.** A new outer contract string,
  copied scalar fields, or a digest projection does not remove the inner v1
  lifecycle dependency and creates cross-version downgrade ambiguity. The v2
  family must be independently encoded and typed.
- **Treat canonical bytes or local socket access as authentication.** Syntax and
  filesystem reachability do not prove endpoint origin, currency, or one-use
  delivery.
- **Stop the supervisor container after only the authenticated wire result.**
  The v2 result remains structural and unqualified; a fresh ADR-0109 host
  observation must be consumed, cross-bound through the v2 host seam, and
  durably retained first.
- **Extend or reinterpret ADR-0110 v1 in place.** V1 has no ordinal two or
  success schema. Changing its meaning would alter immutable historical
  evidence and permit cross-version ambiguity.
- **Create a second v2 attempt slot beside the v1 root.** Two roots would make
  the global replay domain ambiguous. V2 must preserve the one fixed permanent
  slot and treat existing v1 or unknown state as consumed/recovery-required.
- **Reserve first and add recovery later.** Any crash after possible root
  creation would strand the only attempt without a complete classification.
- **Retry when a result or later record is missing.** Missing durable evidence
  never proves a CALL was not delivered or did not succeed.
- **Release and reacquire the global lock between admission, effects, or
  outcome.** Another topology/head/authority transition could invalidate the
  operation while its old evidence still appears structurally equal.
- **Use PID checks after locking or Python-only best-effort fork cleanup.** A
  child can deadlock on inherited state before reaching the check or cleanup.
- **Stop the source first or stop source and supervisor concurrently.** That can
  prevent the supervisor from producing and authenticating the exact
  `clean_stop` successor.
- **Use broad Compose teardown or `down --volumes`.** Name-based scope and volume
  deletion violate exact topology targeting and evidence preservation.
- **Publish success before post-teardown terminal reauthentication.** An old or
  pre-teardown observation cannot prove the final trusted head and teardown
  outcome for this operation.
- **Reuse the pre-effect ADR-0109 cross-binding as terminal evidence.** It
  precedes every stop/teardown effect and cannot authenticate the state after
  those effects; the post-teardown observation is distinct and fresh.
- **Wire a partial path to `trusted-time-stop`.** An operator surface would turn
  dormant structural pieces into accidental effect authority before the five
  gates are complete.
