# ADR 0097: Approval-bound first trusted-time enrollment and recovery

- Status: Accepted (implemented; first `new` enrollment confirmed 2026-08-08)
- Date: 2026-08-08
- Extends: [ADR 0094](0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md)

## Context

ADR 0094 makes enrollment default-deny. The production trusted-time supervisor
fixes `allow_enrollment=False` with no environment override, so its normal
startup path cannot create the first external checkpoint. This is intentional:
sequence 1 changes the durable SQL and remote Storage histories from empty to
enrolled and therefore needs a narrower approval and evidence boundary than an
ordinary supervised start.

A generic temporary toggle inside the background worker would be unsafe. Once
an immutable sequence-1 intent commits, a timeout, disconnect, malformed
provider response, local crash, or lost terminal output cannot prove whether
the object or receipt is absent. Automatically starting over could create a
conflicting history. Letting the normal worker continue could also prepare a
sequence-2 periodic or clean-stop successor before the enrollment result has
been independently reviewed.

An approval message or an earlier admission receipt is not enough. Rebuilding
the images changes the immutable image tuple, and an unenrolled admission made
against earlier images does not qualify the implementation that will perform
enrollment. The operation must be bound to the exact post-merge images, the
fresh fail-closed unenrolled observation for those images, and the complete
nonsecret deployment identity. It also needs a single-use local claim so a
crash or operator retry cannot silently replay one approval.

## Decision

Implement contract `phase6d-one-shot-trusted-time-first-enrollment-v1` as a
dedicated, profile-only Compose service named
`trusted-time-first-enrollment`. It uses the immutable supervisor image and the
same exact database, authority, Auth, and signing-key config/secret mounts, but
it is not the normal supervisor worker. It has no Chrony dependency or Chrony
socket/state mount, exposes no port, runs as UID/GID 10001 on a read-only root
filesystem, drops all capabilities, uses `no-new-privileges`, retains the
existing bounded CPU/RAM/process limits, and has `restart: no`.

The service loads and validates the four staged inputs, records the existing
nonsecret consumption marker, and then waits without opening the runtime
database or provider until the host launcher writes one exclusive release
marker. The launcher must first retire and revalidate all staged inputs and
repeat the exact admission, daemon, topology, image, container, mount, and
approval gates. No release means no enrollment I/O.

Keep the normal production supervisor unchanged at
`allow_enrollment=False`. The one-shot service is the only implementation path
that may request sequence 1. It must complete a full SQL and remote audit,
create or recover only sequence 1 with reason `enrollment`, authenticate the
durable receipt and a bounded full remote postcondition, and exit immediately.
It must never prepare a periodic, transition, or `clean_stop` successor and
must never create sequence 2.

Expose two distinct operations through
[`scripts/enroll_trusted_time_head_anchor.py`](../../scripts/enroll_trusted_time_head_anchor.py):

1. **New enrollment** accepts only an empty authenticated SQL and remote
   history. Any pending intent requires recovery; any confirmed receipt means
   enrollment is already complete. The new path cannot adopt either state.
2. **Pending-intent recovery** requires a separate approval whose operation
   mode is `recover_pending`. It may reconcile only the authenticated
   sequence-1 pending intent or reobserve its already-confirmed sequence-1
   receipt after an ambiguous earlier completion. It cannot prepare a new
   candidate or any successor.

The Make entry points are correspondingly separate:
`trusted-time-enroll-first` and
`trusted-time-recover-first-enrollment`. Neither target is an automatic retry
mechanism, and neither may be invoked from the normal start target.

One exact operation approval binds all of the following:

- operation UUIDv4 and operation mode;
- 40-character lowercase merged Git revision, content-addressed image-
  admission SHA-256, immutable source image ID, and immutable supervisor image
  ID;
- for `new`, a fresh canonical
  `trusted-time-unenrolled-launch-admission-<sha256>.json` receipt produced
  against that exact post-merge tuple; for `recover_pending`, the exact
  original receipt, prior `new` operation UUIDv4, and exact SHA-256 of that
  operation's retained canonical claim; and
- anchor-authority, deployment-identity, runtime-database-identity,
  anchor-project-identity, source-authority, signing-public-key, host-identity,
  principal-identity, and bucket-identity SHA-256 values.

The canonical approval projection uses
`phase6d-first-enrollment-exact-operation-approval-v2`. Immediately before
release the launcher retains
`phase6d-first-enrollment-single-use-claim-v2` as
`trusted-time-first-enrollment-claim-<operation-uuidv4>.json`. After release it
attempts to retain content-addressed
`phase6d-first-enrollment-host-outcome-v1` as
`trusted-time-first-enrollment-outcome-<sha256>.json`. Both files are owner-only
mode `0600` beneath the ignored `artifacts/trusted-time` directory.

Host, principal, and bucket values are retained only as contract-domain-
separated digests. Claims, outcomes, and terminal output contain no database
value, Auth credential, signing private key, session token, provider body,
raw project/principal/bucket value, host name, or secret filesystem path. Every
readiness, operational-control, arming, exposure/new-exposure, broker-action,
alert-delivery, automatic-rearm/resume, paper-trading, and live-trading
authority field remains false.

Before creating topology, the launcher takes the nonblocking global trusted-
time launcher lock shared by normal start, unenrolled admission, enrollment,
and recovery, and holds it through terminal observation, teardown, and outcome
retention. Those host launchers therefore cannot overlap. While holding that
lock and before opening the owner launch environment, the launcher removes only
an authenticated stranded first-enrollment one-shot or exact recognized staged-
input orphans. Container identity, image, service, command, lifecycle state,
security settings, structured-mount or legacy-bind representation, and all four
host source paths must match the one-shot contract. Cleanup never invokes the
release command, never reads staged contents, always removes the exact Compose
project/network, and proves both named volume identities are preserved. Any
extra container, unknown orphan entry, or identity/path drift rejects without
targeted cleanup. `new` permits this crash cleanup only when no claim exists;
any retained claim blocks `new` before Docker inspection or teardown, while
`recover_pending` requires its exact authenticated prior `new` claim.

Immediately before release the launcher atomically publishes an owner-only
immutable single-use claim for the exact approval and operation mode. An
existing claim rejects replay. The claim is never removed, including after
failure, so a crash consumes the approval. A new attempt needs a new operation
UUIDv4, a newly reviewed state, and a fresh exact approval; it does not reuse
the old claim.

The presence of any retained first-enrollment claim quarantines the normal
launcher. Both normal start and fail-closed unenrolled admission must reject
before creating topology, regardless of whether the one-shot outcome is
ambiguous, recovery-required, completed-but-unconfirmed, or confirmed. This
prevents the normal worker from recovering a pending sequence-1 intent or
creating sequence 2 after an ambiguous or confirmed one-shot. The dedicated
`recover_pending` launcher is the only implemented post-claim runtime path.
Independently, this phase unconditionally rejects persistent supervision before
claim lookup, Git, Docker, or launch-environment access. The retained-claim
scan remains defense in depth for admission mode and future start work; deleting
or losing local claim files cannot reopen persistent start.

A recovery approval binds the original pre-mutation unenrolled receipt, the
prior `new` operation UUIDv4, and that operation's exact retained claim SHA-256.
Before release, the launcher reloads the owner-only canonical claim by its
operation-bound filename, verifies its own approval digest and `new` mode, and
requires the receipt, Git revision, immutable source/supervisor image IDs, and
all authority/identity digests to match the recovery approval. It also requires
the original image-admission SHA in that claim to match the original receipt.
If image admission must be freshly reissued for current freshness, only the
current image-admission SHA may differ. A changed revision, image ID, receipt,
or identity digest cannot recover this generation; stop for a separately
reviewed recovery or handoff design. This is compatibility with a current
`image-admission` artifact, not permission to run fail-closed unenrolled
admission again; the normal admission target remains quarantined by the claim.
Secretless Make target `trusted-time-readmit-images` may verify and freshly
admit the exact already-installed image pair only after reproducing the same
image IDs from the sealed reviewed Git context. The separate recovery approval
binds that new content-addressed image-admission SHA and the original
receipt/prior-claim tuple.

The launcher must reserve enough of the image-admission monotonic freshness
window to cross the irreversible boundary. It repeats the exact Git revision,
admission artifact, immutable image, local daemon, fresh unenrolled receipt,
authority/identity digest, container, topology, mount, and release-mode checks
immediately before release. Admission expiry or mismatch before release fails
without enrollment I/O. After release, the final outcome separates
`final_approval_state_validated`, which rechecks the immutable approval
bindings, receipt, images, and daemon identity without applying the TTL, from
`final_image_admission_fresh`, which observes current monotonic freshness.
Expiry makes the freshness gate false and prevents confirmation, but it never
suppresses outcome retention or evidence about a possibly completed operation.

Classify stages fail closed:

- A reused operation UUIDv4 is `approval_already_consumed`. A typed host gate
  rejection before release is `first_enrollment_launch_configuration_rejected`.
  Neither result permits a release or reuse of that operation UUIDv4.
- Before the durable intent commit, a positively classified provider outage
  is `provider_unavailable_before_commit`; configuration and state failures are
  `configuration_rejected` or `first_enrollment_precondition_rejected`.
- Once intent commit begins, every ambiguous or unclassified completion is
  `first_enrollment_recovery_required`. Do not rerun new enrollment and do not
  delete or rewrite SQL or remote evidence.
- If sequence 1 and its receipt may already be durable but the final SQL/remote
  postcondition, cleanup, terminal observation, or equivalent confirmation
  cannot be proven, classify
  `first_enrollment_completed_postconditions_unconfirmed`. Treat this as a
  possibly completed enrollment, not as permission to retry new enrollment.
- New mode observing any authenticated confirmed history is
  `first_enrollment_already_completed`. Malformed or incompatible state fails
  during authentication instead. Every remaining unclassified failure is
  `first_enrollment_failed`.
- Only `first_enrollment_confirmed` is success. It must prove sequence 1,
  reason `enrollment`, exactly one intent and receipt, exactly one authenticated
  remote object with no sequence 2, a stable full remote namespace digest, the
  exact approved identities, retired inputs, and false authority fields.

`first_enrollment_outcome_retention_unconfirmed` is a host-layer fallback, not
a runtime terminal reason. After release it means mutation may have occurred
but the canonical host outcome could not be reobserved durably. Exit nonzero,
preserve the immutable claim plus all SQL and remote evidence, and require
manual review; never infer that enrollment did not occur.

`first_enrollment_launch_lock_release_unconfirmed` is a separate sanitized
host fallback. If the global launcher lock cannot be confirmed released after
an outcome was retained, the command exits nonzero and never reports operational
success, even when the retained outcome records a confirmed sequence 1. This
fallback does not delete, rewrite, or downgrade the already-retained canonical
outcome; it changes only the host invocation result and requires manual review.

After release, the launcher must attempt to retain an owner-only immutable
outcome for every terminal or ambiguous result, including missing or malformed
terminal output, post-release admission expiry, immutable-binding final-gate
failure, cleanup failure, or teardown failure. Confirmed durable outcome
retention is required whether the runtime terminal is successful or fatal;
inability to confirm retention uses the fallback above and can never qualify
success. Preserve any available sequence-1 digests without disclosing secrets.
Canonical host stdout is emitted only after retention; output failure exits
nonzero and never removes an already-retained outcome.
Do not roll back or delete remote objects, SQL intents, SQL receipts, claims,
or outcomes in an attempt to restore an “unenrolled” state.

The launcher removes the exact one-shot container and Compose project network,
proves no project container remains, preserves the named volumes and their
captured identities, and never uses `down --volumes`. A success result is not
qualified until teardown, volume preservation, and durable outcome retention
are confirmed. A teardown failure remains nonzero in the canonical outcome; an
outcome-retention failure instead uses the nonzero sanitized fallback and
requires review of the already-retained claim, SQL, and remote state.

## Consequences

The normal supervisor keeps a simple, permanent enrollment deny boundary while
the only sequence-1 mutation is isolated behind a single-use, exact-identity,
one-shot contract. Fresh enrollment and ambiguous-completion recovery cannot be
confused, and the operator cannot run long enough to create sequence 2.

The implementation landed and its first separately approved `new` operation
confirmed on 2026-08-08. The owner-only immutable claim and content-addressed
outcome are retained locally; the result proves sequence 1 with reason
`enrollment`, one authenticated remote object, no sequence 2, all host gates
true, and every authority flag false. This sanitized status statement is not a
substitute for the exact retained artifacts and does not authorize another
enrollment or recovery operation.

Only a retained, confirmed sequence-1 outcome may change enrollment status
from `UNRUN`. Even that outcome does not reopen normal supervision: the
retained claim continues to block normal start and unenrolled admission. A
later separately reviewed, exact-outcome-bound start change must be implemented
before the normal worker may run, recover anything, or create any successor.
The confirmed outcome also grants no trading authority and does not deploy ADR
0095's watchdog, a sealed terminal-observation issuer, readiness, alerts, new-
exposure gating, or manual re-arm. Those remain later separately reviewed Phase
6 work.

[ADR 0098](0098-canonical-post-enrollment-start-evidence-review.md) implements
the first secretless part of that later boundary: an exact claim/outcome codec,
owner-only unambiguous loader, and non-authorizing review projection that keeps
the historical enrollment tuple separate from a proposed later launch tuple.
It does not reopen normal start, authorize sequence 2, or implement shutdown.
