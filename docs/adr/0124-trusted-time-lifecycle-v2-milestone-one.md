# ADR 0124: Partial trusted-time lifecycle-v2 milestone-one core

- Status: Accepted for an unreachable, injected, partial milestone-one core;
  ADR 0121 milestone one is not complete and no production caller, real
  artifact root, authenticated production transport, Docker effect, recovery
  signer, stop effect, or operational authority exists
- Date: 2026-08-26
- Implements part of:
  [ADR 0121](0121-trusted-time-graceful-stop-lifecycle-v2-implementation-resolution.md)
- Preserves:
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)

## Context

ADR 0121 resolves a deliberately large protocol: one shared v1/v2 lifecycle
root, canonical lifecycle-v2 evidence, mutually authenticated seqpacket
transport, ephemeral key custody, same-lock admission, exact Docker HTTP
effects, two trusted-head reauthentication boundaries, terminal cleanup, and
classification-only recovery. Its rollout permits independently reviewed,
unreachable implementation slices, but forbids any slice from gaining live
stop authority or changing `trusted-time-stop`.

Implementing every ADR-0121 artifact, native owner, transport parser, Docker
projection, effect boundary, and recovery proof in one change would obscure the
first invariant that needs review: v2 evidence must be independently typed,
must reject v1/v2 mixing, and must turn every ambiguous store or fake call into
a burned normal path. This decision records the bounded core now implemented
and, equally importantly, the milestone-one work that remains deferred.

This ADR is an implementation record, not an amendment to ADR 0121. ADR 0121
remains normative wherever this partial core is incomplete.

## Decision

### Implement an independent canonical lifecycle-v2 domain core

`packages/domain/trusted_time_graceful_stop_v2.py` defines independent v2
values and canonical codecs without importing the ADR-0110 v1 lifecycle or
ADR-0111 bridge modules. The implemented values are:

- the exact lifecycle-v2 root field set, fixed ordinal zero, checked
  `admission_started_boottime_ns + 600_000_000_000` operation deadline, and
  ordinary complete-byte root digest;
- the exact progress-record top-level field set, closed stage enumeration,
  normal ordinal map through ordinal twenty-two, per-stage evidence field sets,
  predecessor binding, and content-addressed record name;
- immutable transcript entries and prefix snapshots, gap-free predecessor
  validation, content-addressed transcript name, and the exact domain-separated
  transcript digest;
- the non-circular request-basis, ordinal-one request-intent, lifecycle dispatch
  prefix, and final request construction;
- structurally exact, bounded, canonical transport-envelope decoding for the
  request/result/error frame discriminators, roles, counters, payload ceilings,
  canonical base64, complete payload digest, and 262,144-byte packet ceiling;
- recovery-required and confirmed-success outcome codecs plus the fixed commit
  codec and their checked five-second authorization-window relationships; and
- explicit non-authority facts showing that no production caller, real root,
  real transport, real Docker boundary, stop effect, recovery effect, or
  enabled stop target exists.

The transport-envelope type is deliberately named
`UnverifiedLifecycleV2TransportEnvelope`. Structural decoding is not signature
authentication. A private fake-only capability can wrap it for injected
repository tests. No production verifier can construct that wrapper.

Canonical JSON is UTF-8, sorted, compact, trailing-LF terminated, duplicate-key
rejecting, float/non-finite rejecting, strict about built-in integer and boolean
types, and bounded by ADR 0121's depth, node, and artifact-size limits. Decode
always re-encodes and requires byte equality. The v2 root decoder rejects v1
bytes, and the unchanged v1 decoder rejects v2 bytes.

### Add an injected repository with no real storage implementation

`packages/persistence/trusted_time_graceful_stop_v2.py` defines one private,
process/thread-bound repository over a required `LifecycleV2ArtifactStore`
injection. It has no default root and no filesystem-backed implementation. It
cannot call `open`, `Path`, a socket, Docker, HTTP, or a subprocess.

The repository enforces:

- the existing fixed `.post-enrollment-graceful-stop-attempt-slot` as the only
  root across v1 and v2;
- exact v1-root consumed classification and unknown/mixed-root
  retention-unconfirmed classification;
- staging, orphan, unknown-name, duplicate outcome, gap, predecessor, order,
  cross-root, cross-operation, and deadline disagreement as fail-closed states;
- dedicated stage-family retention methods rather than a public generic append
  method;
- full signed-envelope bytes published before ordinal-two evidence, with exact
  digest-derived result/error names and transcript references;
- burning the repository after any ambiguous root, record, wire, transcript,
  outcome, commit, or readback return; and
- recovery-required outcome commits only. There is deliberately no
  confirmed-success repository writer in this partial slice. A recovery write
  requires an already published classified-prefix transcript, the exact next
  recovery-classification intent bound to that prefix, and a distinct final
  transcript ending at that intent.

Because production signature verification is deferred, reopening a namespace
that contains a terminal wire artifact cannot reauthenticate its signature.
The partial repository therefore classifies such a restart as
retention-unconfirmed. It does not promote structural re-decoding into an
authenticated recovery fact.

The test-only in-memory store models exclusive root creation and staged
immutable publication at the before-create, staging-created, file-fsynced,
renamed, directory-fsynced, and stable-readback boundaries. It never cleans up
ambiguous staging or orphan state.

### Add the separately guarded ADR-0112 lifecycle-v2 handoff

`scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py` now
contains a separately named private v2 snapshot, construction capability,
validator, and consumer. The consumer does not call the existing ADR-0111
supervisor-bridge consumer. It reuses ADR 0112's reviewed pending
authentication, fresh source reconstruction, active-registration consumption,
and second complete source revalidation directly.

The resulting private snapshot binds:

- the exact loaded-wrapper identity;
- one exact lifecycle-v2 admission identity;
- the graceful-stop operation ID, admission digest, and channel digest;
- the origin PID and exact `threading.Thread` object;
- the complete primitive historical and decision-candidate source snapshots;
  and
- the canonical historical receipt bytes and digest derived from those source
  snapshots.

`packages/application/trusted_time_graceful_stop_v2_admission.py` is the only
production-source importer of that private seam. Its builder is private,
requires every input explicitly, creates no root, and has no production caller.
Wrong capability, process, thread, operation, admission, channel, source drift,
or reuse rejects after burning pending and active ADR-0112 state.

The existing public ADR-0112 APIs, loaded wrapper, v1 private snapshot,
ADR-0111 consumer, bytes, and callers remain unchanged.

### Add test-only transport and Docker/effect fakes

`tests/unit/trusted_time_graceful_stop_v2_fakes.py` supplies the only artifact,
transport, and Docker/effect adapters for this slice. It is outside production
packages.

The fake transport accepts one exact request payload/envelope pair, checks the
environment, generation, boot/process epochs, channel, dispatch prefix, and
deadline against one terminal frame, and burns itself at every send/receive
boundary. It supplies the private fake-authentication capability only after
that check. A second exchange always rejects.

The fake Docker surface has no generic request method and no volume-delete
method. Its only methods model supervisor stop, source stop, supervisor remove,
source remove, network remove, and two-volume preservation proof. It enforces
that exact serial order, encodes `v=false&force=false&link=false`, records a
zero volume-delete count, and rejects replay. These facts test the lifecycle
ordering contract; every modeled effect failure burns the fake adapter. They
are not Docker observations or effect authority.

### Keep activation machine-checkably absent

The domain, repository, admission seam, and fake module expose closed
non-authority fact maps. Tests require every value to remain false. AST checks
reject imports of socket, Docker, HTTP clients, and subprocess from the partial
slice, reject a raw `open` call, and require zero production importer of the
private injected repository builder.

`make trusted-time-stop` remains the exact two-line hard close. It prints
`trusted-time-stop is approval-blocked: no effecting approved shutdown operator is implemented`
to standard error and exits 2. This change adds no CLI, Make target, Compose
projection, feature flag, environment switch, migration, credential, signer,
endpoint, root, or production caller.

## Implemented invariants and evidence

The focused native-launcher test suite proves the bounded core currently
implemented:

- canonical root, request-basis, request-intent, dispatch-prefix, final request,
  progress, transcript, envelope, recovery outcome, and commit round trips;
- truncation, whitespace, duplicate-key, boolean-as-integer, deadline drift,
  checked-addition overflow, cross-version bytes, unknown root, mixed root,
  orphan name, stage gap, replay, and predecessor substitution rejection;
- root and record ambiguity at every modeled publication boundary burns the
  repository and never becomes normal retry evidence;
- the exact full terminal envelope bytes select the immutable wire name and
  transcript reference, while wire-publication ambiguity never advances
  ordinal two;
- transport faults before/after fake send and receive burn the one channel and
  never become retransmission evidence;
- supervisor-first/source-second stop, exact removal order, network-last
  teardown, volume proof after teardown, zero volume deletion, and absent
  generic request/delete-volume methods;
- classified-prefix publication, exact next recovery-intent binding, distinct
  final transcript, recovery-required outcome commit, and stable reload for a
  prefix that contains no wire artifact, while the partial repository refuses
  a confirmed-success write; and
- one exact ADR-0112 v2 handoff bound to operation/admission/channel/PID/Thread,
  followed by rejection of reuse.

The unchanged ADR-0112 and ADR-0110 lifecycle suites remain required focused
compatibility gates because this slice edits the former and shares the latter's
fixed root name.

## Explicitly deferred ADR-0121 milestone-one work

This ADR does not declare ADR-0121 milestone one complete. The following work
is still required before that claim is accurate:

- exact canonical authority manifest and selection types, signatures,
  predecessor-chain selection, `new_roots_denied`, and recovery-generation
  rules;
- boot UUID readers, process-epoch objects, peer-credential objects, socket-view
  identities, host/supervisor hello, channel confirmation, challenge/channel
  derivation, and their complete codecs and boundary vectors;
- an Ed25519 verifier/authenticator for every transport frame and a persisted
  authentication path that can reauthenticate retained wire bytes after
  restart;
- the complete clean-stop result and error schemas, terminal projection,
  supervisor cleanup commitment, publication receipt, supervisor FD-table,
  quiescence observation, host cleanup receipt, and every nested equality;
- physical root/record/wire/transcript/outcome/commit repository primitives:
  native owned descriptors, exact owner/mode/inode and no-symlink checks,
  bounded directory inventory, exclusive staging, file fsync,
  `renameat2(RENAME_NOREPLACE)`, directory fsync, stable readback, exact
  EEXIST handling, descriptor registry cleanup, and real fork invalidation;
- a production-independent fake signature verifier with tamper vectors for
  every signed field; the current fake capability checks correlation but does
  not perform cryptography;
- exact Docker request, response-framing, body, projection, connection-identity,
  `/proc`, admission-capture, exchange, trace-entry, result-semantic, and
  volume-preservation schemas plus every fixed ordinal `0..17` vector;
- fake daemon behavior at the HTTP byte/framing/projection boundary. The
  current Docker fake is an operation-order fake, not the ADR-0121 fake daemon;
- exact pre-effect and post-teardown ADR-0109 private issuers and binding seams;
- typed constructors and exhaustive semantic validation for every nested
  ordinal `3..22` evidence object. This slice closes their top-level field sets
  and order but not every nested ADR-0121 schema/equality;
- authenticated recovery-classifier construction, signed recovery envelope,
  durable one-use envelope/nonce consumption, exact candidate/marker
  finalization, unknown-state read-only inspection, and recovery-signer
  custody/zeroization fakes. The partial repository accepts only an injected
  recovery intent after checking its classified-prefix digest; it cannot
  construct or authenticate that intent;
- complete confirmed-success candidate/marker repository sequencing, final
  equality-expired authorization, descriptor disposal/empty-registry proof,
  and post-commit non-authoritative disposal;
- concurrency, fork, PID reuse, wrong-thread, async exception, packet `-1/exact/+1`,
  JSON size/depth/node `-1/exact/+1`, signature tamper, and every STORE/CALL/
  return fault vector required by ADR 0121 but outside the bounded tests above;
  and
- an architecture-boundary policy for these new modules and private seams,
  including reviewed imports/private callsites and the updated production
  source-manifest digest.

Milestone two remains wholly deferred: native endpoint and signer owners,
fork guard, fixed launch profiles, encrypted credential provisioning, tmpfs
mount and key admission, socket endpoint admission, seccomp, real Docker Unix
transport, and every real-root path. Milestones three and four remain wholly
deferred as well.

## Consequences

Reviewers can now inspect canonical v2 lineage, version separation, request
non-circularity, injected publication ambiguity, recovery-only terminal
retention, and the ADR-0112 capability split without reviewing a socket,
credential, Docker daemon, or real artifact root in the same change.

The partial repository is intentionally unusable for operations. In particular,
it cannot authenticate a retained terminal wire after restart, cannot write a
confirmed-success outcome, and cannot reach any effect. Those are honest
fail-closed limitations, not temporary success assumptions.

The new production-source files require central architecture-manifest and
private-callsite pin updates during integration. Those shared pins are not
changed in this lane so concurrent Wave 5 work can reconcile them once.

## Rejected alternatives

- **Describe this as completed milestone one.** The deferred list includes
  required milestone-one schemas, cryptographic verification, physical
  persistence, fake-daemon semantics, and recovery proofs.
- **Treat structural envelope decoding as authentication.** Canonical bytes and
  digest equality do not authenticate the signer. Retained wire state therefore
  fails closed on restart in this slice.
- **Put fakes in production packages.** Test adapters live under `tests/unit` so
  no fake transport or Docker method ships as a runtime adapter.
- **Reuse the ADR-0111 private consumer.** Its identity belongs to the v1 bridge.
  The v2 seam shares ADR-0112 source authentication but has a separate
  capability, snapshot, operation/admission/channel binding, and caller.
- **Add a real filesystem store for convenience.** A Python file implementation
  would bypass the exact native no-follow/fsync/no-replace/fork requirements
  frozen by ADR 0121.
- **Allow a generic progress append or fake Docker request.** Dedicated stage
  families and exact fake methods keep out-of-order transitions and volume
  deletion unrepresentable at the exercised surface.
