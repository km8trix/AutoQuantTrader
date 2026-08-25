# ADR 0112: Durable graceful-stop decision-artifact receipt reauthentication

- Status: Accepted for code-only, read-only historical receipt
  reauthentication and exact dormant ADR-0111 handoff; no live production
  caller, stop admission, lifecycle advance, runtime integration, or shutdown
  effect exists
- Date: 2026-08-18
- Extends:
  [ADR 0103](0103-atomic-operator-attested-post-enrollment-execution-admission.md),
  [ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md),
  [ADR 0106](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md),
  and
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

ADR 0106 can authenticate the complete retained start chain and publish one
content-addressed graceful-stop decision-v1 candidate. Its canonical receipt
bytes are derived from the publishing process's private immutable snapshot;
the returned heap receipt is only a view. The candidate is durable, but no
serialized receipt exists for a later process to trust or decode.

ADR 0111 originally accepted only that exact process-local receipt. Its
dormant host bridge could bind the receipt digest structurally, but could not
establish that a decision candidate reloaded later still had the same
owner-only file identity or was derived from the same authenticated historical
start chain. Treating a caller-supplied receipt, digest, or decision tuple as
equivalent would turn an assertion into authentication.

The strict evidence reader therefore recovers the exact ADR-0106 receipt by
redoing the historical authentication, not by adding a second persistence
transaction or by decoding a new receipt artifact. The dormant ADR-0111 host
request now owns one exact authenticate-and-consume handoff from that reader.
Every live path remains absent until a later composition reviews transport,
current topology, authority, lifecycle, and effects together.

## Decision

### Reconstruct the unchanged v1 receipt instead of persisting one

`scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py`
keeps the existing receipt contract, service, status, and receipt field schema
unchanged:

- contract
  `phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1`;
- service
  `trusted-time-post-enrollment-graceful-stop-decision-artifacts`; and
- status `graceful_stop_decision_candidate_prepared_unqualified`.

No receipt sidecar, receipt decoder, commit marker, mutable persisted index,
durable receipt registry, or new persisted schema is introduced. The durable source of truth remains the
canonical decision-v1 candidate plus the already-retained historical start
chain. A second file would create an avoidable ordering interval in which one
artifact was durable and the other was absent or ambiguous.

The module exposes exactly these new public surfaces:

- `LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt`;
- `load_post_enrollment_graceful_stop_decision_artifact_receipt`;
- `authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt`;
  and
- `revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt`.

There is no public receipt byte encoder or receipt-digest helper. Encoding an
arbitrary live receipt after its source checks would create a mutable-object
TOCTOU surface. The loader instead derives canonical receipt bytes and their
digest from authenticated source snapshots, freezes them into an inert
structural projection, and records a non-authorizing pending binding outside
the object. A separate explicit authenticator consumes that pending binding,
fresh-loads every durable source, and only then activates the already-owned
wrapper. Artifact locations and expected identities are evidence selection and
review assertions only.

### Bind one stable candidate read to the complete historical chain

The loader reads the explicitly selected decision candidate only through
ADR 0103's audited external-binding primitive. The parent directory must be an
external canonical current-user-owned mode-`0700` directory. The candidate
must be a bounded, canonical, content-addressed mode-`0600` regular file with
one link and stable descriptor, named-path, directory, byte, and inode
identity. Symlinks, replacement, aliasing, malformed or noncanonical bytes,
wrong content-addressed names, and ambiguous directory state fail closed.

One successful call is ordered as follows:

1. validate the explicit artifact roots, candidate path, and review
   assertions;
2. read and decode one stable decision-candidate binding;
3. use private snapshot-returning seams to capture the unique committed
   confirmed controller outcome v2, locator, slot/commit names and bytes,
   directory/file identities, and staging absence from raw descriptor-backed
   sources before any mutable retained object is published;
4. through the same kind of private pre-publication seam, capture the locked
   permanent v3-format attempt slot, signed envelope, semantic approval,
   reviewed Git mode/blob/authority bytes and key digests, provenance bytes and
   identities, and public-verification projection;
5. require exact agreement across the candidate decision and every immutable
   historical snapshot, then derive the target, decision, and unchanged
   ADR-0106 receipt exclusively from those raw bytes and values;
6. revalidate the retained historical chain and candidate binding before
   returning an inert loaded object with a non-authorizing pending binding;
7. require a separate explicit authentication call to consume that exact
   pending binding before reviewing arguments or durable sources, fresh-load
   and rebuild the complete source snapshot, exact-compare it with the pending
   immutable snapshot, install the active registration solely from those
   immutable values, and then revalidate the historical chain, candidate, and
   exact registration through return; every failure or asynchronous exception
   burns that active entry; and
8. during later revalidation, consume the active registration before any source
   validation, fresh-load and compare the complete source graph solely against
   that popped immutable record, and keep it burned on every terminal path, so
   replacement, change, replay, or loss of any retained source fails closed and
   a successful return leaves the wrapper inactive again.

Private history snapshots are tagged exact built-in tuple trees containing only
`str`, `bytes`, `int`, `bool`, and exact built-in tuples. Authority consumers
validate the literal tag, length, and primitive type of every slot and read it
only by numeric tuple position. They contain no tuple subclass, heap descriptor,
`Path`, domain object, dataclass, mutable collection, or post-publication
property read.
Outcome, attempt, approval, and receipt objects returned during loading are
transient exact-type/identity construction views only. No attribute, property,
serializer, or equality operation on those heap objects supplies a comparison
or authority fact. They are neither construction sources nor retained registry
state. Revalidation calls the private seams
again, rebuilds a fresh primitive snapshot, and compares the complete immutable
projection. It cannot fall back to the public loaders, object equality, decoded
receipt payload, or `receipt.public_payload`.

The filesystem boundary uses one private native owned-descriptor prerequisite.
Every owner-producing operation is an exact C builtin called directly in the
Python frame that consumes and closes it; no Python helper can return a live
owner. The exact owner exposes only `closed` and idempotent `close`, never a raw
descriptor, `fileno`, detach, pickle, subclass, or mutable attribute. Root and
single-component no-follow opens, file and named-entry Stat9 reads, bounded
offset-zero reads, bounded sorted directory inventories, nonblocking locks,
fsync, and the exact existing-directory candidate writer profile remain behind
exact native type, module-state, main-interpreter, origin-PID, and at-fork
gates. Only immutable bytes, integers, Stat9 tuples, names tuples, or ordinary
success/failure cross back into Python. Fixed owner slots and cleanup-all
ordering close every owner under ordinary or asynchronous failure.

The candidate reader still reaches the reviewed `_read_external_binding` and
`_revalidate_external_binding` seams, while the aggregate controller and attempt
readers use their private pre-publication native snapshot seams. The read-only
load/authentication/revalidation call graph cannot reach ADR 0106's existing
candidate publisher or another write path. It also cannot use raw `open`,
`Path.read_bytes`, legacy `ctypes`, a receipt digest comparison, or another
same-content inode as a substitute for the retained binding.

The reviewed native build now links the owner into a fixed CPython launcher,
registers it before `Py_Initialize`, removes the temporary native name before
target code, and admits only literal profile-specific target IDs. The
operational wheel/image includes only the owner capability; the native bounded
process primitive exists only in the admission and test launcher profiles. This
source/build prerequisite is not yet operationally admitted. ADR-0112 remains
dormant and test-only until exact source and executable/callgraph receipts are
bound, every transitive legacy subprocess caller migrates to the native
transaction, escaped process sessions are contained or excluded, remaining
executable and callgraph integrations use admitted fixed profiles, and the
image/mount admission closes the persistent Chrony-state and read-only leaf
contracts.
Production uses no user-owned disposable environment or operation-time
build/install: the launcher, installed wheel and dependencies, policy, and
complete RECORD/file closure are preinstalled under one root-owned read-only
prefix. Because an ordinary dynamically linked launcher cannot sanitize loader
variables after the OS loader has already consumed them, an admitted
container/service boundary must supply the fixed environment before exec and
bind the launcher, dynamic-loader/libpython closure, executable/import manifest,
image identity, and effective mount receipt. That boundary must also deny
same-UID tracing or process injection. Editable or otherwise user-writable
installations remain development inputs only.

### Bind exact loaded evidence outside the public view

`LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt` is a
non-wire loaded-evidence wrapper. Its entire public structural projection is
limited to:

- `artifact_path` and canonical `encoded` decision bytes;
- `directory_identity` and the exact nine-field `file_identity`;
- source-derived immutable `receipt_encoded` bytes and `receipt_sha256`; and
- its private `_sealed_fields` best-effort structural-view tuple.

It exposes no receipt, decoded decision, retained outcome, retained attempt,
loaded approval, or other nested truth-bearing object. The heap object and all
of its fields, descriptors, `_sealed_fields`, methods, properties, and payloads
are non-authorizing views. The registries use it only as an exact-type,
identity-sensitive weak-reference token; they never copy authority from its
fields. It remains structurally frozen under ordinary access, noncopyable,
nonreplaceable, and nonserializable, but those conveniences are not security
seals. A private-constructor clone, coordinated field/descriptor rewrite,
scalar-equal object, canonical byte string, or caller-supplied digest cannot
acquire either pending or active authentication.

A private external pending registry binds only objects returned by the loader.
It records the exact weak reference, creating PID and exact
`threading.Thread` object, invocation roots and paths, review digest, immutable
historical snapshot, complete source snapshot, canonical receipt bytes, and
receipt digest. It grants no positive authority: the unmodified diagnostic-view
implementation rejects fact access on an inert wrapper, but no property is a
trusted input in either state. A private-constructor clone or a scalar-equal
wrapper cannot authenticate. Authentication consumes and burns the exact
pending entry before argument or durable-source validation. Any mismatch,
exception, process/thread substitution, stale reference, malformed registry
entry, or source drift leaves the wrapper inactive and non-reusable.

Only after that consumption does the authenticator fresh-load every durable
source, rebuild the complete primitive projection, compare it with the
immutable load-time snapshot, and install a distinct active registration made
solely from immutable source and invocation values. It then repeats historical,
candidate, and registry checks through return; every failed or interrupted path
burns the registration. It never reads a wrapper field, seal, post-init method,
property, or public receipt to make that decision.
That active registry binds the exact outer
wrapper, PID, exact Thread, roots, paths, digest assertions, immutable source
snapshot, canonical receipt bytes, and receipt digest. Neither registry
retains a receipt, decision, outcome, attempt, approval, or other nested
truth-bearing object. An interruption at authenticator return may leave the
already caller-owned wrapper active; this is an explicit return-ambiguity
classification, not authority publication to an unknown object. Revalidation
requires that same exact active wrapper identity, atomically consumes the active
record before validation, and fresh-loads and rebuilds the complete primitive
snapshot solely against the popped record. The registration remains burned on
every success, failure, reentrant call, or asynchronous terminal path. After
successful revalidation the canonical diagnostic view rejects again. A second
authentication or revalidation cannot reuse either registry entry.

The shared pending/active registry lock is replaced after fork in the child,
but the original issuer PID deliberately is not. Every child entrypoint checks
that PID before registry locking or weak-reference dereference, making all
inherited pending and active entries inert. Coordinated `object.__setattr__` or
`type.__setattr__` field, seal, method, property, or nested-`Path` relabeling
cannot change the canonical-string authority snapshots because no registry or
authority-bearing source-validation decision reads those public views.

During the active interval the loaded wrapper retains these diagnostic positive
properties, but the heap properties themselves are not authority inputs. A
consumer must use the consuming module-level revalidation result, not a field or
property on the wrapper:

- `decision_artifact_receipt_authenticated=true`;
- `decision_candidate_retention_revalidated=true`;
- `historical_start_chain_authenticated=true`; and
- `verification_only=true`.

Before authentication and after consuming revalidation the canonical
diagnostic view rejects. During the active interval the properties remain
non-authorizing; only successful consuming revalidation supplies the
point-in-time storage and historical-authentication fact. It does
not establish that the historical start is still running, that the target is
current, or that a stop is approved. Every existing ADR-0106 false
qualification field and every ADR-0104 graceful-stop authority field remains
false, including currentness, freshness, stop-signature authentication,
single use, attempt reservation, admission, effect authorization, and
outcome/recovery availability.

### Hand one consumed source snapshot to the dormant host bridge

The ADR-0111 request builder is the sole repository consumer of a pending
loaded wrapper. It does not ask its caller to authenticate the wrapper first.
Instead, one private decision-artifact seam owns the complete transition:
consume the exact pending registration, perform the public authentication's
fresh source rebuild and comparison, immediately consume the resulting active
registration, and revalidate the complete durable source graph again. No
authenticated wrapper state crosses that interval for the host to interpret.
Every failure or asynchronous exception runs pending and active cleanup and
keeps both one-shot entries burned.

Successful consumption returns only a private frozen
`_ConsumedLoadedDecisionArtifactReceiptSnapshot`. It is capability-constructed
and binds the exact loaded-wrapper identity, the host's private bridge identity,
origin PID, exact `threading.Thread` object, complete historical and candidate
source snapshots, canonical root strings, receipt identity values, canonical
receipt bytes, and receipt digest. The private validator requires those exact
identities and recomputes the receipt bytes and digest from the source snapshot;
it never reads a wrapper field or public receipt. A raw ADR-0106 receipt,
canonical bytes, digest, scalar-equal wrapper, private-constructor clone, copy,
replay, wrong thread, forked identity, or drifted source cannot produce this
handoff.

The ADR-0111 builder binds that consumed snapshot to the exact constructed
request in its own one-shot process-local registry. Its terminal binder must
consume the same request, loaded wrapper, and bridge identity before the
ADR-0109 observation can be cross-bound. Only the final host composite may
promote `decision_artifact_receipt_authenticated=true` and
`historical_start_chain_authenticated=true`; the receipt digest in the public
ADR-0111 wire remains structural and independently substitutable bytes carry
no authentication. The existing public revalidation function still consumes
the active registration and returns only a boolean for its separate test-only
surface.

### Enforce a zero-caller read-only boundary

The architecture contract pins the exact public `__all__`, loaded-wrapper
state and facts, private helper callsites, and project, standard-library, OS,
audited-filesystem, and native-owner imports. The loader and all transitively
reachable private helpers are read-only. The module's pre-existing candidate
writer remains reachable only from the pre-existing preparation path.

The same boundary requires the private pre-publication snapshot seams and
primitive-only snapshot shapes. It rejects fallback public-loader calls,
receipt payload decoding, truth construction from or retention of mutable
dependency objects,
`Path` or domain objects inside snapshots, and any reader-reachable write,
currentness, replay, admission, or effect capability.

The loaded-wrapper type and the three private consumed-snapshot seams have one
production importer: ADR 0111's dormant host bridge. The public loader has no
live production caller, so the complete composition remains zero-caller.
Tests exercise it only against injected temporary artifact roots. Mutation
tests reject writer reachability, unaudited reads, helper aliasing or dynamic
lookup, unreviewed fact promotion, seal-field removal, public receipt decoding,
expected-receipt injection, CLI growth, scalar/raw receipt handoff, and any
runtime consumer.

The public ADR-0112 flow adds no CLI subcommand or option, Make workflow,
lifecycle writer, provider or database access, network, signer, private key,
signal, container or network teardown, outcome, recovery executor, watchdog,
or trading consumer. Its only host-bridge integration is the private,
same-process, effect-free evidence handoff above. The decision-artifact module
remains excluded exactly once from Docker build contexts and has zero runtime
caller. Its native prerequisite now includes the pinned build-only compiler
stage, fixed launcher, final-image manifest, and CI packaging matrix; admission
receipts, process-callsite migration/containment, and writable-mount hardening
remain open. None is yet an operational receipt or stop consumer.
`trusted-time-stop` remains the existing exact hard-close target.

### Preserve the remaining live-ordering deferrals

ADR 0112 now closes durable receipt reconstruction, point-in-time
revalidation, and the exact private handoff into ADR 0111's dormant host
request. It does not close any live ordering or authority boundary.

Before any stop effect, later work must still provide, in one explicit
fail-closed ordering:

1. authenticated, bounded, replay-safe host-to-supervisor request/result
   transport with explicit origin and failure semantics;
2. same-lock fresh topology, stop-authority, trusted-head, and operation
   admission before reservation or effect;
3. a separately versioned lifecycle successor with pre-CALL intent,
   post-CALL result, confirmed-success, and recovery-required retention across
   every ambiguity;
4. explicit at-fork invalidation and inherited-lock cleanup for every later
   transport, admission, lifecycle, and effect registry; and
5. reviewed signal, source stop, exact container/network teardown, named-volume
   preservation, terminal reauthentication, and durable outcome choreography.

## Consequences

A later process can now rederive an inert exact public ADR-0106 receipt
projection from durable evidence, then either explicitly authenticate its
already-owned wrapper for the standalone consuming revalidator or pass that
still-pending exact wrapper to the dormant ADR-0111 builder, which owns
authentication and immediate consuming revalidation. Both paths detect
candidate or historical-source drift. Operators do not need to retain the
original process-local ADR-0106 object, and no unauthenticated receipt file
becomes a new source of truth.

The result remains dormant, historical, and verification-only. It promotes
only ADR 0111's decision-receipt and historical-start-chain facts. It does not
make the decision current, authenticate the separate stop signature, consume a
durable stop replay slot, advance ADR 0110, qualify transport, topology,
lifecycle, effect, or permit any shutdown action. No receipt sidecar, decision
candidate, lifecycle record, or operational stop artifact is written by the
ADR-0112 load/authentication/revalidation APIs, and no operational stop is
attempted. The installed extension and executable/import manifest belong only
to the separately admitted native/image prerequisite.

## Rejected alternatives

- **Persist a receipt sidecar after the candidate.** Two separately durable
  files introduce missing/partial/reordered states without adding evidence;
  the receipt is deterministic from already-authenticated sources.
- **Expose receipt encoding/digest helpers, decode caller-supplied receipt
  bytes, or accept an expected receipt digest.** A live receipt can drift
  between validation and encoding; canonical structure and equality are
  assertions, not historical authentication or stable file identity.
- **Trust the decision candidate alone.** The candidate does not authenticate
  the retained outcome, locator, v3 attempt, signed start envelope, reviewed
  authority, provenance, or start tuple by itself.
- **Revalidate only bytes or a SHA-256.** Same-content replacement can change
  the owner-only file and directory identity that the stable read authenticated.
- **Pass a raw ADR-0106 receipt, receipt bytes, digest, or decoded decision to
  ADR 0111.** None carries the consumed source snapshot, exact loaded-wrapper
  identity, or one-shot bridge association, so every such substitution is
  rejected.
- **Add currentness, stop authority, replay, or effects.** None follows from a
  historical decision receipt, and the required live protocols remain absent.
