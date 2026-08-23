# ADR 0106: Authenticated historical start chain graceful-stop decision candidate

- Status: Accepted for code-only historical authentication and offline candidate
  publication; stop admission and shutdown effects remain absent
- Date: 2026-08-16
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0103](0103-atomic-operator-attested-post-enrollment-execution-admission.md),
  [ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md),
  and
  [ADR 0105](0105-inert-post-enrollment-graceful-stop-operator-attestation.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)
  and
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)

## Context

ADR 0104 froze pure graceful-stop target and decision projections, but its
target builder accepted caller-supplied SHA-256 values for the post-enrollment
start attempt slot and signed start envelope. Those values were explicitly
unqualified bindings. ADR 0105 consequently left decision-v1 authoring
unsupported: the detached-signature workflow could decode an exact decision,
but no supported command could prove that decision came from the one durable
confirmed start chain or publish its content-addressed bytes.

The remaining gap in this slice is historical authentication, not current stop
authority.
It must independently reload the exact committed controller outcome, its
embedded shutdown locator, the permanent v3-format start-attempt slot, and the
external signed start envelope. It must derive every target identity from
those revalidated artifacts rather than accept construction facts from a raw
tuple. It must remain entirely before current topology, trusted-head, stop
replay, admission, and effect boundaries.

## Decision

### Expose a strict retained v3-format start-attempt loader

The execution-admission module exposes
`RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt`,
`load_retained_post_enrollment_operator_attested_execution_attempt`, and
`revalidate_retained_post_enrollment_operator_attested_execution_attempt`.
The loader reads only fixed owner-only slot
`.post-enrollment-start-execution-attempt-slot` from the canonical ignored
trusted-time artifact directory. It requires the exact canonical current
contract `phase6d-post-enrollment-start-execution-attempt-v3`, bounded bytes,
one regular current-user-owned mode-`0600` inode with one link, stable
descriptor and named-path identity, exact file and directory readback, and the
already-frozen v3 authority, signature, semantic-v2, provenance, image, and
witness fields.

Exact historical
`phase6d-post-enrollment-start-execution-attempt-v2` bytes remain recognized as
a permanently consumed historical start attempt, but are ineligible for the
normal graceful-stop decision binder. They are not translated, rewritten,
deleted, or treated as v3. Missing, malformed, ambiguous, replaced, or
partially durable slot state fails closed. The private immutable retained
snapshot binds canonical bytes, digest, absolute path, and inode identity. The
returned heap receipt is only a non-authorizing view and grants no stop, replay,
currentness, operational, or trading authority.

### Bind one decision from the complete authenticated historical chain

`scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py`
exposes:

- error `TrustedTimePostEnrollmentGracefulStopDecisionArtifactError`;
- non-authorizing receipt view
  `TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt`; and
- API `prepare_post_enrollment_graceful_stop_decision_candidate`.

The receipt contract is
`phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1`, service
`trusted-time-post-enrollment-graceful-stop-decision-artifacts`, and status
`graceful_stop_decision_candidate_prepared_unqualified`.

One preparation call must:

1. use the private prepublication controller seam to capture and durably
   revalidate the unique committed
   `phase6d-post-enrollment-start-retained-controller-outcome-v2` raw bytes,
   slot/commit bytes, native Stat9 and inventory identities, staging absence,
   complete confirmed semantics, and exact embedded shutdown-locator/topology
   projection before any retained object is published;
2. use the private prepublication attempt seam to capture and revalidate the
   exact locked permanent v3-format slot bytes and immutable attempt semantics;
3. through that same immutable attempt snapshot, authenticate the explicitly
   named external owner-only signed start envelope, complete nested semantic v2
   approval, exact reviewed `100644` start-authority Git revision/path/mode/blob
   and public-key digests, public signature/statement/authority identities, and
   stable approved provenance bytes, Stat9 identities, revision, source image,
   supervisor image, boot session, and creation projection;
4. require exact agreement across the immutable outcome, locator/topology,
   attempt, approval, envelope, Git, and provenance snapshots for every shared
   operation, approval, claim, controller, revision, image, provenance,
   statement, signature, authority, and envelope identity; returned mutable
   outcome/attempt/approval objects are exact-type/identity construction views
   only—their attributes, properties, serializers, and equality never supply a
   comparison or authority fact;
5. derive the attempt-slot and envelope SHA-256 values from those loaded bytes,
   build the ADR-0104 target, bind the caller's distinct canonical UUIDv4 stop
   operation, and build the exact decision-v1 bytes; and
6. revalidate every retained source before returning an exact durably retained
   decision candidate.

The six `--expected-*` arguments are review assertions. They must equal
identities derived from authenticated artifacts and cannot substitute for
loading, semantic validation, or revalidation. In particular, the attempt-slot
and envelope digests are never used as caller-injected target facts. The stop
UUID is the sole semantic choice made by the caller; the two path arguments
choose only the evidence to access and the external directory in which to
store the candidate.

### Publish only an inert external candidate

The supported isolated command is subcommand `prepare-decision` with
`allow_abbrev=False` and exactly these flags:

- `--graceful-stop-operation-id`;
- `--start-operator-attested-approval-artifact`;
- `--decision-candidate-directory`;
- `--expected-controller-outcome-sha256`;
- `--expected-durable-shutdown-locator-sha256`;
- `--expected-start-execution-attempt-slot-sha256`;
- `--expected-start-operator-attestation-envelope-sha256`;
- `--expected-start-operation-id`; and
- `--expected-start-approval-sha256`.

The output directory must already exist outside the repository as one
canonical current-user-owned mode-`0700` directory. The writer publishes exact
mode-`0600` canonical bytes at
`trusted-time-post-enrollment-graceful-stop-decision-v1-<sha256>.json` using
exclusive creation, file and directory durability, exact readback, and final
named-path rebinding. An exact retry is idempotent. Conflict or ambiguous
publication fails closed without deleting possible evidence.

`make trusted-time-prepare-post-enrollment-graceful-stop-decision` is a reserved
interface for supplying only the nine explicit values above. Its current
recipe still enters the project through `uv run`, which can execute the local
PEP-517/Hatch hook before authentication, so the Make invocation is blocked and
test-only until the fixed preinstalled root-owned read-only launcher/runtime,
its exact policy target, and its static native CPython prerequisite freeze. It
must not construct a user-owned runtime. It is not an operator procedure or
a dependency or alias of `trusted-time-stop`. The binder script is excluded
from Docker build contexts and is not added to the reviewed fixed runtime-input
inventory.

### Keep every live and stop authority closed

The binder has no stop authority manifest or verifier, signer, private key,
clock, randomness, Docker or Compose client, database, provider, network,
currentness reader, stop-attempt slot, stop admission, outcome writer,
recovery capability, signal sender, teardown operation, or production caller.
Its receipt truthfully reports only authenticated historical relationships and
durable inert candidate publication. `historical_start_chain_authenticated`,
the individual historical revalidation fields,
`decision_candidate_semantically_bound`,
`external_stop_attestation_required`,
`later_atomic_stop_admission_revalidation_required`,
`historical_evidence_only`, and `verification_only` are true. Currentness,
freshness, stop-signature authentication, single use, stop admission, stop-slot
reservation, stop effect, stop outcome/recovery availability, and every
ADR-0104 authority field are false.

The existing decoder-only graceful-stop operator-attestation workflow remains
a separate offline stage. It consumes a reviewed decision-v1 candidate to
prepare statement bytes and later publicly verify a detached signature; it
does not rediscover or authenticate the historical start chain. Conversely,
this binder does not load the stop authority or authenticate a stop signature.

`trusted-time-stop` remains the exact no-prerequisite, two-line hard-close
target. It emits the existing approval-blocked message and exits 2 without
invoking Python or Docker.

ADR 0111 can accept the exact live process-local decision-artifact receipt from
this module and bind its digest into an unqualified clean-stop request.
[ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)
now adds a separate zero-caller read-only flow that reconstructs an inert exact
unchanged v1 receipt projection only after a stable decision-candidate read and
complete historical-chain reauthentication. Explicit authentication then
consumes the exact non-authorizing pending binding and repeats the full durable
authentication before activating the already-owned wrapper; later revalidation
consumes that active binding. It persists no receipt sidecar and grants no
currentness or stop authority. ADR 0111 does not yet consume the authenticated
loaded wrapper; that integration remains required before live orchestrator use.

## Consequences

An operator can now obtain a content-addressed decision-v1 candidate only from
the exact authenticated historical start chain, then review that candidate
before the separate ADR-0105 signing workflow. Historical v2 start attempts and
v1 controller outcomes remain preserved but cannot enter this normal path. No
current host state or shutdown permission is inferred from a historically
authenticated decision.

Before any stop attempt can be reserved or any container can be signaled, a
later reviewed design must still provide same-lock fresh topology and bounded
trusted-head evidence, a distinct permanent stop-attempt protocol, and a
progress-sensitive durable stop outcome/recovery protocol across every
CALL/STORE boundary. ADR 0107 closes only the clean-stop false-positive seam:
the exact current request must produce its own paired remote readback and
durable receipt, while an unchanged-head no-candidate result or a receipt
recovered for an older intent is unconfirmed. It deliberately adds no
no-new-record success contract or durable stop outcome. The supervisor's
process-local boolean and generic `status=stopped` line still do not prove a
durably retained ADR-0099 stop result.

## Rejected alternatives

- **Continue accepting caller-supplied target digests.** Expected digests are
  review assertions only; artifact-derived bytes must determine the target.
- **Accept or upgrade a historical v2 start-attempt slot.** Its contract lacks
  the v3 signed-envelope and reviewed-Git-authority bindings. It remains
  consumed historical evidence and requires a separate recovery decision.
- **Accept controller-outcome v1 or a recovery-required v2 outcome.** V1 has no
  durable locator, and recovery-required is not a confirmed normal start.
- **Fold decision preparation into detached-signature verification.** Keeping
  historical-chain authentication and stop-signature verification distinct
  prevents either stage from silently supplying the other's authority.
- **Reserve the stop slot or add currentness/effects now.** Durable recovery and
  a durably retained, host-reauthenticated clean-stop result are not yet
  available; ADR 0107's fail-closed receipt invariant is not a substitute.
