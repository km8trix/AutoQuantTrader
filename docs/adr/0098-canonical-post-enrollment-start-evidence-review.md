# ADR 0098: Canonical post-enrollment start evidence review

- Status: Accepted (evidence review implemented; start and stop remain blocked)
- Date: 2026-08-08
- Extends: [ADR 0097](0097-approval-bound-first-trusted-time-enrollment.md)

## Context

The first approval-bound `new` enrollment defined by ADR 0097 completed on
2026-08-08. Its owner-only immutable claim and content-addressed host outcome
are retained locally. The outcome confirms sequence 1 with reason `enrollment`,
one authenticated remote object, no sequence 2, a stable full remote audit,
all eight host gates true, and every authority flag false.

That result changes enrollment status from `UNRUN` to `CONFIRMED`, but it does
not make normal supervision safe. The enrollment claim binds the historical
revision and images that created sequence 1. Any implementation that can
authenticate that state and create sequence 2 necessarily requires a later
revision and new immutable images. Requiring those two launch tuples to be
equal would make the post-enrollment change impossible; ignoring the old tuple
would discard the evidence that established the durable chain.

The existing enrollment launcher has a canonical claim builder and a decoder
used only for pending-intent recovery. It has no public decoder for the
successful `new` claim and no semantic host-outcome decoder. The host outcome
wrapper alone checks only that bytes exist, its path is absolute, and a caller-
supplied confirmation boolean is a boolean. A future normal start must not rely
on that wrapper or on filename presence.

## Decision

Add a standard-library-only evidence codec in
`packages/domain/trusted_time_enrollment_evidence.py`. It owns no filesystem,
clock, randomness, process, database, provider, operational-control, broker,
alert, readiness, re-arm, or trading authority.

The codec authenticates the exact retained wire contracts rather than
translating them into the repository's typed canonical-JSON format. Each input
must be bounded ASCII, reject duplicate keys and nonfinite values at every
nesting level, use the exact compact sorted representation followed by one line
feed, and match its externally supplied lowercase SHA-256.

For the retained claim, require:

- the exact approval-v2 and claim-v2 field sets and contract versions;
- the expected UUIDv4 and `new` mode with both recovery fields null;
- one exact 40-character revision, content-addressed image admission, and two
  distinct immutable image IDs;
- all nine digest-only deployment identities and the exact pre-mutation
  unenrolled-admission digest;
- a recomputed approval digest over exactly the approval projection;
- fixed claimed status and host-launcher service; and
- every authority field plus `authority_granted` false.

For the retained outcome, require:

- the exact content-addressed outcome-v1 field set and digest;
- an embedded approval byte-equivalent in meaning to the claim approval, with
  the same recomputed approval digest and exact claim digest;
- fixed confirmed status and `first_enrollment_confirmed` reason;
- all eight exact host gates true;
- every authority field, `authority_granted`, and
  `database_secret_disclosed` false; and
- an exact runtime terminal bound to the claim's mode and identity digests.

The runtime terminal must prove an exact integer sequence `1`—a Python boolean
is rejected—reason `enrollment`, `new_intent_completed`, a completed full audit,
valid result and namespace digests, readback equality, no pending-intent
recovery, and exactly one upload-or-idempotent-duplicate result. The decoder
returns immutable typed digest-only evidence, never a mutable decoded mapping
or an authority grant.

This first bridge contract intentionally accepts only the actual confirmed
single `new` history and requires an unambiguous artifact inventory: exactly
one first-enrollment claim and exactly one first-enrollment outcome, selected by
the externally reviewed operation ID and hashes. A deployment with recovery
claims or multiple outcomes needs a separately reviewed successor contract; it
must not guess which artifact is terminal.

Add a descriptor-relative host loader in
`scripts/trusted_time_post_enrollment_evidence.py`. It accepts only a canonical
absolute owner directory at mode `0700`, reads exact mode-`0600`, current-owner,
single-link regular files with `O_NOFOLLOW`, bounds every read, and requires the
directory identity and sorted inventory to remain stable across both reads.
Unrelated image-admission and unenrolled-admission artifacts may coexist, but
another enrollment claim or outcome makes this v1 inventory ambiguous.

The pure review builder keeps two tuples separate:

1. `confirmed_enrollment.enrollment_launch` is the historical tuple whose
   retained evidence established sequence 1; and
2. `proposed_launch` is the later revision/admission/image tuple under review
   for normal supervision.

Its canonical contract is
`phase6d-post-enrollment-start-evidence-review-v1`. Status is always
`review_required`; persistent start, sequence 2, shutdown, and every operational
or trading authority are explicitly false. It is a secretless review
projection, not an approval artifact and not a launcher.

Keep both lifecycle commands fail closed. `trusted-time-start` still rejects
before claim lookup, Git, Docker, or owner-environment access, and the shutdown
target remains unavailable. This ADR does not read the retained production
artifacts, runtime environment, database, or provider and does not start a
container.

## Required later runtime boundary

Before a later normal-start implementation may sign or prepare a successor, it
must hold the global launcher lock and compare the typed retained binding with
a fresh authenticated SQL state and a bounded stable full remote audit. The
comparison must prove the same sequence-1 intent, receipt, current head,
semantic digests, deployment identities, namespace digest, exactly one remote
object, no pending recovery, and no higher sequence.

That later change must separately freeze and review:

- a single-use start approval and durable start claim/outcome policy;
- the exact authorization point at which sequence 2 may be prepared;
- behavior for a crash after runtime reauthentication but before or during the
  first successor;
- a graceful shutdown contract that signals the supervisor first, confirms an
  authenticated `clean_stop` successor, then stops the source while preserving
  named volumes; and
- the image admission and operational approval needed to execute the resulting
  runtime.

None of those policies is inferred from the confirmed enrollment or from this
review projection.

[ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)
subsequently freezes those policies and implements only their pure/read-only
contract pieces. The staged release, persistent start, sequence 2, and graceful
stop remain unimplemented and separately operationally approval-blocked.

## Consequences

Post-enrollment development can now consume the retained evidence through one
high-level fail-closed decoder instead of importing the enrollment launcher or
reimplementing partial checks. The old enrollment tuple can be preserved while
a distinct future tuple is reviewed.

The system remains externally enrolled but not persistently supervised. No
sequence 2, periodic or transition checkpoint, `clean_stop`, watchdog terminal
issuer, readiness consumer, alert consumer, new-exposure gate, trading
authority, or manual re-arm authority is added by this decision.
