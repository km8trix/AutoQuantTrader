# ADR 0109: Code-only clean-stop terminal reauthentication

- Status: Accepted for a point-in-time, read-only host observation with only
  ADR 0111's dormant zero-caller composition; durable stop outcome/recovery,
  watchdog use, and every stop effect remain absent
- Date: 2026-08-16
- Extends:
  [ADR 0095](0095-dormant-provider-neutral-trusted-head-watchdog-state.md),
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  and
  [ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

ADR 0108 preserves the exact receipt created by one in-process `CLEAN_STOP`
request, but deliberately does not prove that its signed object is the remote
namespace terminal. A later host boundary needs to accept an arbitrary already
confirmed clean-stop sequence, re-read its exact SQL evidence, authenticate the
complete provider namespace, prove that sequence `N + 1` is absent during the
observation, and reject SQL drift around those provider reads.

That proof is still narrower than a graceful-stop attempt. It has no exact
ADR-0104 stop operation ID, signed stop decision, current topology lease,
permanent attempt slot, durable progress/outcome, recovery state, signal, or
teardown authority. The provider exposes no atomic multi-request namespace
snapshot, and the currently admitted Supabase principal is not a separately
provisioned read-only watchdog principal. The safe next slice is therefore a
code-only, effect-unconnected, point-in-time verifier and one-shot issuer; ADR
0111 is its sole dormant production importer and has no production caller.

## Decision

### Freeze one exact public observation contract

Host module
`scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py`
defines contract
`phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1` and exports
only:

- `POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION`;
- `TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration`;
- `TrustedTimePostEnrollmentCleanStopTerminalPostcondition`;
- `TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer`;
- `TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected`; and
- `prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer`.

The preparer accepts only an exact validated database URL and one exact
authority, provider-credential, and public-verifier configuration. Preparation
captures a private copy of those inputs, excludes credential secrets from every
public digest and representation, binds the originating process and thread,
starts one deadline, and returns an immutable one-shot issuer. SQL and provider
resources are created lazily inside the issuer's sole call.

The result status is
`provider_terminal_observed_under_stable_sql_authenticated`. Its only positive
truth property is
`provider_terminal_observed_under_stable_sql_authenticated=true`. That name is
intentionally point-in-time and does not mean lasting currentness.

The sealed result binds the exact clean-stop sequence and reason, confirmed and
local counts, terminal local ordinal, predecessor, current host head, anchor
byte and semantic identities, intent/readback/receipt identities, receipt UTC
instant, remote namespace count and observation digest, every nonsecret
authority identity, observation start/completion/deadline, issuer binding, and
read-only configuration digest. It carries no operation ID, stop target,
decision, slot, topology, signal, teardown, or outcome field.

### Require the exact S1/provider/S2 observation

One successful invocation performs this order under a single absolute
suspend-aware 120-second monotonic deadline:

1. Load a fresh full-replay SQL snapshot S1. Require `complete_replay=true`, no
   pending intent, an exact receipt/intent/record/authenticated-tip chain,
   reason `CLEAN_STOP`, sequence `N >= 3`, confirmed count `N`, terminal local
   ordinal equal to the local transition count, the current host head equal to
   the terminal record, exact readback/record bytes, and all admitted authority
   identities.
2. Attest the provider identity, then perform authenticated full pass A over
   the entire remote prefix. Listing must be bounded and gap-free at exactly
   sequences `1..N`; every object is downloaded, decoded, signature-verified,
   authority-bound, and predecessor-linked.
3. Perform independent full names pass B. Its ordered namespace count and
   digest must equal pass A, and both audited boundary identities must still
   match.
4. Perform a late exact singleton list for sequence `N`, download and
   reauthenticate that exact terminal object again, then require the late
   sequence `N + 1` list to be empty.
5. Reattest the exact provider identity after all namespace reads.
6. Load a fresh full-replay SQL snapshot S2 with the same validation as S1 and
   require exact projection equality between S1 and S2.

The extra terminal GET is deliberate even though pass A already downloaded
`N`. Omitting it would leave terminal bytes less current than the late list.
The `N + 1` read is also separate and late; an empty next sequence is not
inferred from the earlier full listing. Repeated SQL reads are two independent
repository snapshots, not two reads from one retained transaction.

The provider verifier preflights `N` against the fixed full-audit bound before
provider access. Pass A and pass B traverse the full prefix rather than a
terminal-only suffix, so duplicates, gaps, out-of-range names, reordered pages,
boundary substitution, record substitution, signature failure, identity
drift, or a changed namespace digest fail closed.

### Bound time, SQL, provider, and cleanup authority

Linux uses `CLOCK_BOOTTIME`; Darwin uses `mach_continuous_time` with one captured
timebase. Unsupported or invalid clocks fail closed. Deadline equality is
expired. The guard rejects process/thread crossing and monotonic regression,
checks before and after provider operations, and routes each SQL cursor
execution through the same deadline. Connect timeout is one second, statement
timeout is one second, lock timeout is 500 milliseconds, and PostgreSQL is
created with `default_transaction_read_only=on`.

The SQL repository surface used by this module is exactly
`load_head_anchor_startup_snapshot` and `discard_head_anchor_snapshot`. The
provider wrapper exposes exactly identity attestation, bounded page listing,
exact-sequence listing, and download, plus private deadline activation. It has
no upload method. Cleanup is registered before an owned resource can escape;
ordinary cleanup failure rejects success, while `KeyboardInterrupt`,
`SystemExit`, and other asynchronous `BaseException` values are not replaced by
deadline or cleanup errors.

“Read-only provider” describes this method-narrowed local wrapper, not external
IAM. The admitted Supabase credential can still have insert permission because
the existing append-only anchor writer uses it. Provider authentication token
refresh can also mutate provider-side session state. Supabase RLS visibility,
append-only object policy, stable list semantics, and the admitted provider
identity remain trust prerequisites. This ADR does not claim WORM storage,
administrator immunity, a dedicated reader principal, or atomicity across the
multiple HTTP requests.

### Seal the result and keep every broader claim false

The issuer and result are process- and thread-bound, registry-sealed,
nonconstructible, immutable, noncopyable, nonreplaceable, nonserializable, and
invalid after fork. The issuer is one shot. Failed issuance revokes a partially
registered result before it can escape. Configuration identity and values are
revalidated before resource creation, after observation, after cleanup, and
before issuance.

Every broader property remains false, including all ADR-0104 target,
historical-chain, signature, topology, single-use, slot, admission, retry,
outcome-retention, signal, supervisor/source/network/container/volume removal,
teardown, operational-control, exposure, broker, trading, and rearm/resume
properties. The ADR-0108 aliases for provider-terminal currentness,
no-new-record authentication/success, durability, durable stop outcome, slot,
admission, and effect also remain false. `authority_granted=false` and
`database_secret_disclosed=false` are explicit. The in-process one-shot seal
does not make `single_use_authenticated` true for a future durable operation,
and validating a durable SQL receipt does not make this result or a stop
outcome durable.

Its only production importer is ADR 0111's dormant host bridge, which may use
only the exact one-shot consume/consumed-validator snapshot seams. Neither
module has a production caller, `main`, CLI, Make target, stdout result,
persistence writer, signer, upload, SQL mutation, Docker/Compose connection,
signal, shutdown, teardown, watchdog, or trading consumer. This module is
included in the reviewed source revision and excluded from Docker build
context. `make trusted-time-stop` remains the exact hard-closed exit-2 target.

### Treat the result as a bounded observation, not lasting currentness

The ordered passes, late terminal GET, empty `N + 1`, final identity
reattestation, and equal S1/S2 projections detect the reviewed classes of
drift during this invocation. They cannot prevent a write immediately after
the last relevant read or after return. A provider could also change and
restore state between non-atomic requests without every transient state being
observable. The result is therefore truthful evidence of one bounded
observation interval, not a lease, freshness grant, or continuously current
terminal.

ADR 0111 now supplies only the dormant one-shot composition seam. Its host
binder burns one exact postcondition first, retains the immutable consumed
registry snapshot, and cross-checks the ADR-0108 projection. The resulting
composite preserves this ADR's bounded positive observation but still reports
lasting currentness, topology, lifecycle, transport, durability, admission,
outcome, and every effect as false.

## Consequences

The minimum safe code-only slice can be implemented without a deployed
provider-terminal watchdog issuer, watchdog process, or durable stop outcome
because it has zero operational consumers and grants zero authority. It closes
the verifier logic and local sealing design needed by a later phase, but it
does not close the graceful-stop workflow.

A future effecting stop phase must separately:

1. bind an exact current ADR-0104 stop operation, signed stop decision, and
   current topology lease;
2. reserve one permanent stop-attempt slot and durably store progress before
   every ambiguous external effect;
3. consume or freshly revalidate this observation directly inside the ordered
   admission/effect transaction rather than trust a serialized process seal;
4. retain a terminal success/failure/unknown outcome with no automatic retry;
5. prove the exact supervisor/source/network removals while preserving named
   volumes; and
6. recover every CALL/STORE ambiguity before another attempt is allowed.

[ADR 0110](0110-dormant-durable-graceful-stop-lifecycle-repository.md) now
implements only the dormant persistence foundation for that ordering. Its one
fixed immutable ordinal-zero attempt root is also the permanent replay slot,
and its bounded typed stage records form a gap-free append-only predecessor
chain. The real artifact root has no production creator. Its only terminal is
the non-authorizing `recovery_required` classification for the missing live
integration; no positive post-signal or confirmed-success constructor is
reachable. ADR 0111 now bridges the exact ADR-0108 current request and consumes
this ADR's one-shot observation as a dormant unqualified same-process
composite. Authenticated live transport, same-lock authority/topology admission,
and lifecycle-v2 integration remain required before any positive constructor
or effect; serialized or caller-supplied digests remain insufficient.

The Phase 6E watchdog remains separate. It still needs its own independently
deployed failure domain, preferably a dedicated externally enforced read-only
provider principal, periodic observations, durable state, alert path, and the
360-second freshness policy with equality stale. A clean-stop-specific
point-in-time result must not be fed into the dormant reducer as if it were a
continuously current watchdog lease.

No provider, database, Docker, signer, live key, or operational stop action was
performed to accept this ADR.

## Rejected alternatives

- **Trust only SQL or the ADR-0108 process result.** Neither proves the remote
  full namespace terminal at this later host observation.
- **List only `N` and `N + 1`.** That misses historical gaps, duplicates,
  substitutions, and invalid signatures elsewhere in the namespace.
- **Use one pass or omit the late terminal GET.** That weakens detection of
  namespace and terminal drift during a non-atomic provider observation.
- **Reuse one SQL transaction for S1 and S2.** A repeatable-read transaction
  would hide committed drift instead of detecting it.
- **Call the current Supabase credential read-only.** The wrapper is
  method-narrowed, but external authorization still permits the existing
  writer capability.
- **Serialize, persist, or print the sealed result.** ADR 0111 now provides a
  separately versioned structural wire, but the process/thread seal still
  cannot become trustworthy live cross-process evidence without authenticated
  transport and origin plus fresh issuance or revalidation.
- **Wire the issuer into `trusted-time-stop` now.** Observation without a
  durable operation-bound outcome/recovery state would make ambiguous effects
  unsafe to retry.
