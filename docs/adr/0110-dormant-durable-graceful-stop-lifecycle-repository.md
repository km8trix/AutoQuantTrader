# ADR 0110: Dormant durable graceful-stop lifecycle repository

- Status: Accepted for a code-only append-only filesystem repository; no
  production operation-bound reservation, post-signal evidence,
  confirmed-success outcome, or shutdown effect exists
- Date: 2026-08-16
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md),
  [ADR 0105](0105-inert-post-enrollment-graceful-stop-operator-attestation.md),
  [ADR 0106](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md),
  and
  [ADR 0109](0109-code-only-clean-stop-terminal-reauthentication.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

ADR 0109 authenticates one bounded `CLEAN_STOP` terminal observation, but that
process-local result is not bound to an approved stop operation, current
topology lease, permanent replay reservation, or durable stop outcome. It also
cannot make a later signal, container removal, network removal, or outcome
write safe to retry after a lost return.

The future graceful-stop choreography contains irreversible ambiguity
boundaries. A process can lose control after the supervisor signal was sent but
before the result was stored, after a container or network removal returned but
before its observation was retained, or while the terminal outcome itself was
being published. Reserving an attempt first and designing recovery later would
leave exactly those states eligible for accidental replay.

A separate attempt slot and progress root would create an additional ordering
gap: either file could exist without the other. A mutable progress file would
also require overwriting the only durable statement of the last known state.
Free-form append APIs, caller-selected stage names, and optimistic inference
from a missing later record would turn partial storage into authority.

## Decision

The dormant host module is
`scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py`, with service
identity `trusted-time-post-enrollment-graceful-stop-lifecycle`. Its only
accepted artifact directory is an explicitly injected ignored root joined with
the exact `trusted-time` child. It has no ambient root discovery, default
production reservation path, or production caller.

The frozen contracts and retained classifications are:

- attempt contract `phase6d-post-enrollment-graceful-stop-attempt-v1`, whose
  only status is `graceful_stop_attempt_reserved`;
- progress contract `phase6d-post-enrollment-graceful-stop-progress-v1`, whose
  terminal repository status is
  `operation_bound_supervisor_bridge_required`; and
- retained-outcome contract
  `phase6d-post-enrollment-graceful-stop-retained-outcome-v1`, whose only
  status is `recovery_required` and whose only reason is
  `operation_bound_supervisor_bridge_unavailable`.

The exact progress transcript is domain-separated by
`phase6d-post-enrollment-graceful-stop-progress-transcript-v1`, and the fixed
terminal commit marker uses
`phase6d-post-enrollment-graceful-stop-outcome-commit-v1`. Neither auxiliary
contract adds another phase, root, authority, or success classification.

These are storage classifications, not authority or evidence that any
supervisor signal or teardown effect occurred.

### Make the fixed root the permanent attempt slot

Freeze one global, fixed-name, immutable attempt-root artifact named
`.post-enrollment-graceful-stop-attempt-slot`. It is ordinal zero of the
graceful-stop lifecycle, the repository lock point, and the permanent replay
slot; there is no separate attempt/replay slot file, per-operation root, or
root-before-slot state. The recovery-only terminal-publication protocol uses
its own fixed shared publication slot and commit marker, but neither is a
second attempt or progress root. The root's canonical payload binds the exact
stop operation, signed-v2 graceful-stop envelope from ADR 0105, the envelope's
structurally bound ADR-0104 start-chain projection, exact durable shutdown
locator, and reviewed evidence identities admitted by its contract. It does
not consume or retain ADR 0106's decision-artifact receipt or historical source
artifacts, so every historical-authentication fact remains false. Its phase is
exactly `attempt_reserved`, and it has no predecessor.
Those retained bindings are structural and non-authorizing. This module has no
reviewed-Git stop-authority loader; future admission must freshly reauthenticate
the authority and current evidence instead of inferring either from the root.

Creation is owner-only, exclusive, no-follow, single-link, bounded, file- and
directory-fsynced, read back, and rebound to its exact inode and bytes before a
receipt can be returned. Once creation may have begun, existence, conflicting
bytes, ambiguous durability, or an unreadable candidate permanently closes the
normal-attempt domain. Absence is retry-relevant only when it is positively
established before creation begins by a future operation-bound admission. No
cleanup path deletes, renames, truncates, rewrites, or replaces a possible
root.

The dormant repository has no production caller capable of creating this root.
Its real artifact root therefore remains unchanged by this slice. Unit tests
can reserve only an injected temporary artifact root and supply no evidence
that the real artifact root exists or is absent.

### Append only typed, predecessor-bound stages

Every later record is a new immutable artifact with one exact contract-defined
stage, the next gap-free ordinal, the root SHA-256, and the exact predecessor
artifact SHA-256. The content-addressed typed filename is derived from the
stage, ordinal, and payload digest; it is never caller-selected. A record is
accepted only when a bounded stable inventory contains one exact root and one
gap-free, hash-linked prefix with no duplicate ordinal, duplicate stage,
alternate predecessor, orphan, skipped transition, unrecognized file within
the dedicated graceful-stop lifecycle filename namespace, or future contract.
Unrelated names in the shared trusted-time directory are outside that
namespace and ignored only within the bounded stable shared inventory. They
are neither consumed nor rejected as lifecycle entries, but exceeding the
separate total shared-directory entry ceiling fails closed.

The repository exposes no generic `append(stage, payload)` operation. Each
recognized transition has a dedicated typed construction path and exact
predecessor rule. There is no reset, delete, rewrite, truncate, rollback,
retry, resume, replay, stage-skipping, arbitrary metadata, or free-text reason
surface. Reload and revalidation report only the exact durable prefix; missing
later evidence never proves that an external call did not occur. If a stable
bounded inventory and exact receipt identities cannot be proven, status
`retention_unconfirmed` withholds every prefix receipt rather than expose a
partially trusted projection.

This slice has exactly one progress successor: ordinal one, phase
`operation_bound_supervisor_bridge_required`, staged only through
`.post-enrollment-graceful-stop-progress-staging` and retained as
`trusted-time-post-enrollment-graceful-stop-progress-01-<sha>.json`. There is
no ordinal two, signal, post-signal, effect-complete, or success phase in this
contract.

The recovery-only terminal publication is staged through the fixed
`.post-enrollment-graceful-stop-outcome-staging` name, retained as
`trusted-time-post-enrollment-graceful-stop-outcome-<sha>.json`, and committed
through the fixed `.post-enrollment-graceful-stop-outcome-commit-staging` and
`.post-enrollment-graceful-stop-outcome-committed` names. Those publication
artifacts are not a second attempt or progress root. They can retain only the
frozen `recovery_required` classification and cannot qualify or imply a
confirmed graceful stop.

Any failure after a root may exist, any CALL/STORE uncertainty, and any
partial, conflicting, skipped, unknown, or future artifact is recovery-required
and never normal-retry-eligible. Recovery-required is a durable classification,
not recovery authority. This ADR adds no recovery executor or automatic
continuation.

### Stop before post-signal or confirmed claims

This repository slice cannot construct a positive post-signal record or a
confirmed-success graceful-stop outcome. ADR 0111 now supplies the dormant,
unqualified operation-bound bridge and one-shot consumption seams that bind:

1. an operation-bound bridge to the exact ADR-0108 current-request
   `CLEAN_STOP` result; and
2. a one-shot, same-operation consumption seam for an issued, bounded ADR-0109
   SQL/provider/SQL terminal observation. Its reads were fresh only at issuance;
   consumption grants no freshness or currentness.

A generic supervisor `status=stopped` line, process exit, current boolean,
serialized process seal, caller-supplied digest, old `CLEAN_STOP`, or empty
next-sequence observation cannot substitute for either seam. Even ADR 0111's
valid same-process composite remains a bounded, unqualified observation until a
future authenticated live transport, same-lock topology and authority
admission, lifecycle-v2 schema/integration, and effect transaction bind it to
the exact operation, topology lease, root, and progress prefix.

The later effect protocol must durably append the exact pre-CALL intent before
each ambiguous supervisor signal, supervisor removal, source stop/removal, and
network removal. It must append the separately authenticated result before
advancing, preserve both named volumes, and retain either one exact confirmed
terminal or one recovery-required terminal without automatic retry. Those
positive post-signal transitions are specified as future dependencies, not
implemented by this ADR.

### Keep the repository dormant and method-narrowed

The implementation is an append-only filesystem repository only. It may use
bounded owner-only file and directory operations required for immutable
retention and revalidation. It has no CLI, `main`, Make target, Compose or
Docker command, subprocess, signal, provider, network, SQL, signer, upload,
runtime worker, controller, caller-supplied effect callback, topology reader,
stop-authority loader, admission consumer, or production caller. Its private
cleanup helper can invoke only internally constructed descriptor-close,
flock-release, and directory-iterator-close operations; it is not an
effect-injection seam.

All public receipts and loaded projections are non-authorizing. Root retention
does not authenticate the stop decision, current topology, trusted head,
single use for an effect, admission, signal delivery, clean-stop completion,
container or network removal, teardown, or outcome success. Retry,
operational-control, readiness, re-arm/resume, exposure, broker, paper-trading,
and live-trading properties remain false.

This dormant seam must not be constructed in a process that can fork while a
lifecycle descriptor or flock is active. It exposes no subprocess, fork,
process-launch, or at-fork registry/cleanup surface. Safe inherited-lock cleanup
and explicit at-fork invalidation remain mandatory before any live bridge may
integrate the repository.

The public evidence/codec surface consists only of the three canonical record
types, the three `RetainedTrustedTimePostEnrollmentGracefulStop*` receipt
types, `TrustedTimePostEnrollmentGracefulStopRecoveryState`, their strict
canonical encoders/decoders, exact `load_retained_*` and
`revalidate_retained_*` functions, and
`inspect_post_enrollment_graceful_stop_recovery_state`. There is no public
reserve, append, retain, retry, continuation, or recovery writer.

Mutation is reachable only through the private
`_build_post_enrollment_graceful_stop_lifecycle_repository` test seam and its
private `_reserve_attempt`, `_retain_bridge_required_progress`, and
`_retain_recovery_required_outcome` methods. The builder requires an explicit
absolute `ignored_root`; it has no default. Its construction capabilities,
owned-descriptor/FFI helpers, receipts, repository state, and `_new_*` and
`_persist_*` functions remain private and have no production importer or
re-export.

The repository module is included in the reviewed source digest and excluded
from Docker build context. Architecture guards pin its exact dependencies,
filesystem capability, public surface, private seams, absence of production
callers, and absence from Make and runtime wiring. `make trusted-time-stop`
remains the exact no-prerequisite, two-line hard-close target that prints the
approved failure and exits 2 without invoking Python or Docker.

ADR 0111 now implements the missing request/result and one-shot terminal
cross-binding as dormant code, but it does not call this repository's private
writer or advance the v1 prefix. Ordinal one remains terminal for v1. Retaining
the bridge result, pre-CALL intent, authenticated post-CALL result, and either
confirmed success or recovery-required outcome requires a separately reviewed
lifecycle version; existing immutable v1 artifacts must not be rewritten or
reinterpreted.

## Consequences

The repository can now freeze the durable ordering primitive needed before a
future stop admission is permitted to create the permanent root. Injected test
repositories can retain only the fixed recovery-required terminal described
above. The root and its append-only chain make replay closure and the last
durably known stage one atomic lineage rather than two independently orphanable
artifacts.

Accepting this ADR does not reserve the real artifact root. No post-signal fact
or confirmed-success stop can be retained, and no Docker, database, provider,
signer, signal, or teardown action is performed. Same-lock current topology
and trusted-head evidence, the reviewed-Git stop-authority loader,
authenticated live transport for ADR 0111, same-lock current-topology and
authority admission, lifecycle-v2 integration, exact-ID effect choreography,
final volume-preserving teardown proof, and a separately approved recovery
workflow remain later ordered phases. The live bridge must also close the
inherited-flock/fork lifecycle before any production construction. ADR 0110 v1
still has no ordinal-two, post-signal, or confirmed-success schema.

Unknown and future artifacts inside the dedicated lifecycle namespace
deliberately fail closed rather than being ignored. A future contract that adds
post-signal or confirmed transitions must be a new reviewed version and cannot
reinterpret or rewrite an ADR-0110 root or prefix.

## Rejected alternatives

- **Create an attempt/replay slot and then a progress root.** A crash can orphan
  either side. Ordinal zero is the permanent attempt slot and root together;
  this does not preclude a later distinct terminal-publication commit slot.
- **Use per-operation roots.** Multiple operation-named roots would make the
  supposedly global one-attempt replay domain ambiguous.
- **Rewrite one current-state file.** Overwrite and rename ambiguity can erase
  the only durable predecessor. Every transition is a new immutable record.
- **Expose a generic append API.** Caller-selected stages or payloads can skip
  mandatory pre-CALL intent and manufacture a later state.
- **Treat a missing successor as proof that a call did not happen.** Lost
  CALL/STORE control is recovery-required, never retry evidence.
- **Add post-signal or success constructors now.** ADR 0111 provides only the
  dormant unqualified operation-bound bridge and one-shot ADR-0109 consume
  seam. Authenticated live transport, same-lock admission, lifecycle-v2
  integration, and the effect protocol do not exist yet.
- **Serialize ADR 0108 or ADR 0109 as the outcome.** Their process seals and
  bounded observation meanings do not become durable stop authority on a wire.
- **Wire the repository to `trusted-time-stop`.** Persistence without the
  complete operation/currentness/admission/effect chain would only make unsafe
  partial operations easier to launch.
