# ADR 0121: Trusted-time graceful-stop lifecycle-v2 implementation resolution

- Status: Accepted as a design-only implementation resolution; no transport,
  key, endpoint, lifecycle-v2 artifact, admission, recovery writer, runtime
  caller, stop effect, or operational authority is implemented or authorized
- Date: 2026-08-25
- Extends:
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)
  and
  [ADR 0116](0116-fail-closed-replay-safe-graceful-stop-composition-ordering.md)

## Context

ADR 0116 freezes the graceful-stop composition as one non-separable sequence:
authenticated transport, same-lock current admission, lifecycle v2, fork-safe
ownership, and ordered effects with distinct pre-effect and post-teardown
reauthentication. It originally left the implementation choices unresolved.
That protects the current runtime from a partial activation, but it is not yet
specific enough to implement or review the prerequisites independently.

Those choices were security boundaries, not interchangeable details.
A local socket without peer and key binding would authenticate only pathname
reachability. A counter without a boot and process epoch could restart into an
accepted replay domain. A new lifecycle root beside ADR 0110 v1 would create two
permanent stop slots. Reusing ADR 0112's current handoff would import the exact
ADR-0111 v1 bridge identity that lifecycle v2 must reject. A general Docker or
Compose command surface could preserve the nominal order while still deleting a
named volume or targeting a replacement container.

This ADR resolves those choices before implementation. It remains documentation
only. The exact paths, contracts, algorithms, bounds, state machine, recovery
policy, and rollout constraints below are normative future requirements, not
claims about current code or deployment state.

## Decision

### Preserve one non-separable activation boundary

The five ADR-0116 gates remain one production activation boundary. They may be
implemented and reviewed in unreachable slices, but no slice may acquire live
stop authority, dispatch an operation request, reserve the real lifecycle root,
or alter `trusted-time-stop` until the complete integrated implementation and
fault proof are accepted.

The future live controller must execute this order while one exact global
launcher-lock lease remains continuously held:

1. qualify the fork guard, transport authority, exact endpoint, endpoint
   processes, and a mutually authenticated preflight channel; no operation
   payload may be sent;
2. freshly authenticate current topology, current trusted head, installed stop
   authority and signed operation, and the ADR-0112 historical chain, then
   construct one one-shot admission bound to that exact channel;
3. consume that admission to reserve the one permanent lifecycle root and
   durably retain the clean-stop request intent;
4. dispatch exactly one request, retain exactly one authenticated result or
   error, then durably retain and complete authenticated transport-owner cleanup
   before any effect;
5. perform every effect and reauthentication STORE/CALL pair in state-machine
   order, then durably retain and complete empty-mount/terminal-owner cleanup;
6. only after that cleanup result is durable, publish and revalidate exactly
   one confirmed-success outcome candidate, dispose every remaining success-
   relevant candidate handle, and pass the final equality-expired precommit
   authorization check; then publish its one fixed commit. A failure path may
   instead publish only a recovery-required outcome. The authorization check is
   the whole-operation cutoff, while the fixed commit is the terminal lifecycle
   boundary; and
7. after an ordinal-23 confirmed-success fixed commit and outside the lifecycle
   and its deadline, dispose of already-empty
   non-authority registries and close the lease descriptor. This post-commit
   disposal owns no secret, effect, observation capability, or durable
   candidate, and cannot alter the committed classification.

Before root creation may have begun, failure closes the channel and requires a
completely fresh lock, channel, admission, and challenges. After root creation
may have begun and before outcome-candidate publication may have begun, every
failure is recovery-required. Once candidate or fixed-marker publication may
have begun, failure is `outcome_commit_unconfirmed`: only the exact candidate/
marker rules below apply, and an unauthorized confirmed-success candidate alone
is retention-unconfirmed rather than permission to create a second outcome.
No transport error or apparently unperformed call reopens the normal-attempt domain. Once an exact
fixed commit is stably authenticated, no later disposal error, signal, deadline
read, or process-exit status may invalidate, replace, or reclassify it.

### Use one lifecycle and replay root across v1 and v2

The only lifecycle root remains the existing fixed permanent filename:

```text
.post-enrollment-graceful-stop-attempt-slot
```

V2 uses root contract
`phase6d-post-enrollment-graceful-stop-lifecycle-root-v2`, service
`trusted-time-post-enrollment-graceful-stop-lifecycle-v2`, status
`graceful_stop_lifecycle_v2_reserved`, phase `root_reserved`, and ordinal zero.
The fixed file is simultaneously the lifecycle root and the global one-use
replay slot. There is no v2 sidecar root, version selector, per-operation root,
or root alias.

An absent fixed root may be reserved as v2 only after the one-shot admission is
consumed. An exact ADR-0110 v1 root means the permanent slot is already consumed
and normal v2 is denied forever. An unknown, future, noncanonical, partial, or
mixed v1/v2 root or namespace is retention-unconfirmed and permits neither a v1
nor v2 action. V1 files are never migrated, wrapped, renamed, deleted, or
reinterpreted.

The exact v2 root field set is:

- `contract_version`, `service`, `status`, `lifecycle_version`, `phase`, and
  `ordinal`;
- `environment`, `graceful_stop_operation_id`,
  `graceful_stop_target_sha256`, `graceful_stop_decision_v1_sha256`,
  `graceful_stop_operator_attestation_envelope_sha256`, and
  `historical_decision_receipt_sha256`;
- `admission_sha256`, `topology_sha256`, `topology_lease_sha256`,
  `trusted_head_sha256`, and `stop_authority_sha256`;
- `transport_authority_manifest_sha256`, `transport_key_generation`,
  `host_transport_key_id`, and `supervisor_transport_key_id`;
- `boot_epoch_sha256`, `host_process_epoch_sha256`,
  `supervisor_process_epoch_sha256`, and `channel_id`;
- `supervisor_container_id`, `source_container_id`, `project_network_id`,
  `chrony_command_socket_volume_identity_sha256`, and
  `chrony_state_volume_identity_sha256`;
- `admission_started_boottime_ns`, `clean_stop_result_deadline_boottime_ns`,
  `operation_deadline_boottime_ns`, and `root_created_at_utc`.

`lifecycle_version` is the integer `2`, `phase` is exactly `root_reserved`, and
`ordinal` is the integer zero. UTC values are audit metadata only. No wall-clock
value supplies freshness, expiry, ordering, or authority.
`admission_started_boottime_ns` is the one admission-start sample defined below.
`operation_deadline_boottime_ns` is exactly its checked sum with
`600_000_000_000` nanoseconds: the 600-second normal-path precommit
authorization cutoff, not a durable-marker completion time. Both values equal
the consumed admission projection; neither is caller supplied.

The root is created exclusive/no-follow through the admitted native owned-file
boundary, file- and directory-fsynced, read back, canonical-decoded, rebound to
the exact directory/file identity and bytes, and revalidated before exposure.
Once creation may have begun, absence cannot be inferred from an error.

### Freeze canonical v2 storage contracts and namespaces

V2 adds these independent canonical storage contracts:

- progress record
  `phase6d-post-enrollment-graceful-stop-lifecycle-record-v2`;
- transcript
  `phase6d-post-enrollment-graceful-stop-lifecycle-transcript-v2`;
- immutable signed result/error wire-envelope artifacts using the transport
  envelope contract itself as their byte contract;
- terminal outcome
  `phase6d-post-enrollment-graceful-stop-lifecycle-outcome-v2`; and
- terminal commit
  `phase6d-post-enrollment-graceful-stop-lifecycle-outcome-commit-v2`.

Progress records use exact content-addressed names
`trusted-time-post-enrollment-graceful-stop-v2-record-<ordinal:02d>-<sha256>.json`.
Immutable transcript snapshots use
`trusted-time-post-enrollment-graceful-stop-v2-transcript-<last-ordinal:02d>-<transcript-sha256>.json`.
The exact signed-wire names are
`trusted-time-post-enrollment-graceful-stop-v2-wire-result-<clean_stop_result_sha256>.json`
and
`trusted-time-post-enrollment-graceful-stop-v2-wire-error-<clean_stop_error_sha256>.json`.
The outcome uses
`trusted-time-post-enrollment-graceful-stop-v2-outcome-<sha256>.json` and the
fixed commit marker
`.post-enrollment-graceful-stop-outcome-committed-v2`. Fixed staging names are
`.post-enrollment-graceful-stop-v2-record-staging`,
`.post-enrollment-graceful-stop-v2-transcript-staging`,
`.post-enrollment-graceful-stop-v2-wire-result-staging`,
`.post-enrollment-graceful-stop-v2-wire-error-staging`,
`.post-enrollment-graceful-stop-v2-outcome-staging`, and
`.post-enrollment-graceful-stop-v2-outcome-commit-staging`. Staging presence on
load is ambiguity, never cleanup permission.

Every name in this lifecycle namespace is relative to the exact owner-only
directory `<ignored-root>/trusted-time`; the two wire final paths and staging
paths are therefore literal children of that directory. The stable-loaded
absolute no-symlink directory path is `artifact_directory_path`; each wire
`artifact_path` is exactly that string, `/`, and its digest-derived `file_name`,
with no normalization or alternate spelling. Both path strings and the
directory device/inode are root/admission-bound rather than caller supplied. A
wire artifact's
complete file bytes are the exact canonical signed transport envelope received
in one seqpacket, including every unsigned field, `payload_base64`,
`signature_ed25519_base64`, and the canonical trailing LF. There is no storage
wrapper, extracted-payload substitute, or signature sidecar. The result and
error files remain bounded by the exact 262,144-byte envelope limit. All their
fields and payloads are nonsecret by design.

`clean_stop_result_sha256` and `clean_stop_error_sha256` are ordinary SHA-256
over the respective complete canonical signed-envelope file bytes. The
corresponding `payload_sha256` is the envelope's already-signed ordinary
SHA-256 over the decoded complete canonical payload bytes.
`signature_sha256` is ordinary SHA-256 over the exact decoded 64-byte Ed25519
signature. These three digests are distinct and never substituted.

After the one `recvmsg` and before ordinal two may be retained, the host must
bound the still-complete packet, canonical-decode and re-encode it byte-for-
byte, authenticate its schema/signature/channel/counter/deadline/payload, and
take the final equality-expired publication-authorization sample before
publishing those same bytes. Publication uses exclusive no-follow creation of the
one frame-type staging name as owner-only mode `0600`, complete write and file
fsync, `renameat2(RENAME_NOREPLACE)` to the digest-derived final name,
parent-directory fsync, then stable no-follow readback, canonical re-encoding,
signature re-verification, and file/name/digest revalidation. `EEXIST` permits
only byte-identical stable revalidation. Any uncertain write/fsync/rename,
staging file, orphan wire file, result/error pair, second digest, wrong mode or
inode, readback drift, or unknown wire prefix is retention-unconfirmed; it is
never deleted or normalized.

The publication receipt contract is
`phase6d-post-enrollment-graceful-stop-wire-envelope-publication-receipt-v2`,
service `trusted-time-post-enrollment-graceful-stop-lifecycle-v2`, status
`wire_envelope_published`. Its exact fields are `contract_version`, `service`,
`status`, `environment`, `graceful_stop_operation_id`, `root_sha256`,
`artifact_kind`, `artifact_directory_path`, `artifact_directory_device`,
`artifact_directory_inode`, `artifact_path`, `file_name`, `file_device`,
`file_inode`, `file_mode`, `file_size`, `signed_envelope_sha256`, `envelope_contract_version`,
`frame_type`, `payload_contract_version`, `payload_sha256`,
`signature_sha256`, `key_generation`, `signing_key_id`, `channel_id`,
`lifecycle_dispatch_prefix_sha256`, `message_counter`, `deadline_boottime_ns`,
`directory_fsync_completed`,
`stable_readback_completed`, and `publication_authorized_boottime_ns`. Artifact kind is
exactly `signed_result_envelope` or `signed_error_envelope`; mode is integer
`384` (`0600`), directory/file device/inode and size are positive bounded
integers, path/name obey the exact construction above, and both completion
booleans are true. File size equals the complete signed-envelope byte length and
is at most 262,144; artifact kind/frame type/path/name/full-envelope digest map
exactly to result or error; envelope/payload/signature/key/channel/counter/
dispatch-prefix/deadline fields equal the decoded authenticated envelope; and
`publication_authorized_boottime_ns < deadline_boottime_ns`. The sample is
taken immediately before staging creation; it is not a postpublication
completion timestamp, and stable readback after the cutoff cannot reclassify
the authenticated bytes. Its digest is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/wire-envelope-publication-receipt/v2`,
one NUL byte, and the complete canonical receipt.

Every progress record has exactly these top-level fields:

- `contract_version`, `service`, `status`, and `lifecycle_version`;
- `graceful_stop_operation_id`, `root_sha256`, `ordinal`, `stage`, and
  `predecessor_sha256`;
- `effect_kind`, `deadline_boottime_ns`, `evidence`, and `recorded_at_utc`.

`status` is `graceful_stop_lifecycle_v2_progress_retained` and
`lifecycle_version` is `2`. `effect_kind` and the exact object in `evidence` are
selected by the typed stage. There is no public or private generic append API.
Each stage has a dedicated constructor, allowed predecessor, exact evidence
schema, and maximum size.

Intent evidence except ordinal one has exactly `target_identity_sha256`,
`arguments_sha256`, `admission_sha256`, `channel_id`, and
`call_deadline_boottime_ns`. Result
evidence has exactly `intent_sha256`, `responder_identity_sha256`,
`disposition`, `result_semantic_sha256`, `call_started_boottime_ns`, and
`call_completed_boottime_ns`. The two reauthentication result stages add the
exact fields `observation_semantic_sha256`, `binding_semantic_sha256`,
`observed_head_sha256`, and `provider_identity_sha256`. The volume-proof result
instead adds `command_socket_volume_identity_sha256`,
`state_volume_identity_sha256`, `docker_api_trace_sha256`, and
`volume_delete_call_count`, whose value must be integer zero. A typed decoder
rejects fields from any other stage rather than normalizing them.

For ordinal one, `arguments_sha256` is the digest of an exact non-circular
request basis, not the digest of the later signed request. The basis uses
`contract_version="phase6d-trusted-time-head-anchor-clean-stop-request-basis-v2"`,
service `trusted-time-head-anchor-clean-stop-v2`, status
`operation_bound_clean_stop_request_basis_retained`, and exactly the final
request fields defined below except `request_basis_sha256`,
`request_intent_sha256`, and `lifecycle_dispatch_prefix_sha256`. Its digest is
SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/clean-stop-request-basis/v2`, one
NUL byte, and the complete canonical basis. The ordinal-one constructor derives
that basis only from the stable root/admission and fixed constants, stores its
digest as `arguments_sha256`, and exposes no caller-selected basis object.
Ordinal-one intent evidence has the five intent fields above plus exactly
`admission_started_boottime_ns` and `operation_deadline_boottime_ns`; they equal
the basis/root/admission and reproduce the checked 600-second sum.
`request_intent_sha256` is then ordinary SHA-256 of the complete canonical
ordinal-one progress-record bytes. Only after that record is stably read back
may the dispatch prefix and final request be constructed.

Ordinal two is deliberately not the generic result shape. Result-stage
evidence has exactly `intent_sha256`, `responder_identity_sha256`,
`disposition`, `clean_stop_result_artifact_path`,
`clean_stop_result_artifact_name`, `clean_stop_result_sha256`,
`envelope_contract_version`, `frame_type`, `payload_contract_version`,
`clean_stop_result_payload_sha256`, `clean_stop_result_signature_sha256`,
`terminal_projection_sha256`, `key_generation`, `signing_key_id`, `channel_id`,
`lifecycle_dispatch_prefix_sha256`, `message_counter`,
`deadline_boottime_ns`, `wire_publication_receipt`,
`wire_publication_receipt_sha256`, `call_started_boottime_ns`, and
`call_completed_boottime_ns`. Disposition is `authenticated_result`, frame type
is `clean_stop_result`, counter is integer one, and the nested publication
receipt must re-encode and hash to its repeated digest and exact result file.
The evidence path/name/full-envelope/payload/signature/schema/key/channel/
dispatch-prefix/counter/deadline values equal the nested receipt and decoded
envelope, and
`call_started_boottime_ns <= call_completed_boottime_ns` while
`call_completed_boottime_ns <= publication_authorized_boottime_ns < deadline_boottime_ns`.

Error-stage evidence has the identical correlator/publication shape with
`clean_stop_error_artifact_path`, `clean_stop_error_artifact_name`,
`clean_stop_error_sha256`,
`clean_stop_error_payload_sha256`, and `clean_stop_error_signature_sha256` in
place of the five result artifact fields, omits
`terminal_projection_sha256`, and adds `error_code` and `failure_boundary`;
disposition is `authenticated_error` and frame type is `clean_stop_error`. The envelope/payload contracts, supervisor
key/generation, channel, lifecycle dispatch prefix, counter, absolute deadline,
receipt, and complete canonical bytes must agree at every nesting. Exactly one
of these two typed
ordinal-two records and exactly its one wire artifact may exist.
The same artifact/receipt/evidence equalities and timestamp inequalities apply
to the error names and bytes.

Every Docker-effect intent additionally has exactly
`docker_request_semantic_sha256` and
`docker_post_inspect_request_semantic_sha256`. Its result repeats both exact
digests, embeds the complete exact `result_semantic` object whose canonical
domain digest equals its repeated `result_semantic_sha256`, and adds the exact
two-element
`docker_method_trace_entry_sha256_list` in primary-CALL then post-inspect order;
disagreement with the intent is a schema failure, not an alternate observation.
The volume-proof intent instead has the exact two-element
`docker_request_semantic_sha256_list` in command-socket then state-volume order,
and its result repeats that list, embeds its complete exact `result_semantic`,
and adds the matching exact two-element
`docker_method_trace_entry_sha256_list`. These fields bind the complete
canonical method, path, ordered query, fixed request headers, and absent body
defined below. The closed semantic schemas below bind every HTTP status,
framing/body/typed-projection digest, complete primary and post-inspect exchange,
complete connection identity, daemon continuity, trace entry, timestamp, and
outcome. They are not caller-selected summaries or digest-only substitutes.

The transcript contract is
`phase6d-post-enrollment-graceful-stop-lifecycle-transcript-v2`, service
`trusted-time-post-enrollment-graceful-stop-lifecycle-v2`, status
`graceful_stop_lifecycle_v2_transcript_retained`. Its exact top-level fields are
`contract_version`, `service`, `status`, `lifecycle_version`, `environment`,
`graceful_stop_operation_id`, `root_sha256`, `last_ordinal`, `last_stage`,
`entry_count`, and `entries`. Each `entries` element has exactly `ordinal`,
`stage`, `record_artifact_kind`, `record_contract_version`,
`record_artifact_sha256`, `predecessor_sha256`, `wire_artifact_kind`,
`wire_artifact_path`, `wire_artifact_file_name`, and `wire_artifact_sha256`.
Ordinal zero is the root,
has record kind `root`, stage `root_reserved`, and null predecessor/wire fields.
Every later element has record kind `progress`, names the exact typed stage at
that ordinal, hashes the complete canonical progress-record bytes, and names
the immediately prior record artifact hash. Only ordinal two has non-null wire
fields: they are exactly `signed_result_envelope` plus its result name/digest or
`signed_error_envelope` plus its error name/digest, and they must equal the
complete nested publication receipt and artifact references in that progress
record. Every other entry's four wire fields are null. Thus the transcript
unambiguously binds both the ordinal-two evidence record and the immutable
signed bytes it authenticates. Entries are strictly ordered and gap-free from
zero through `last_ordinal`;
`entry_count == last_ordinal + 1`, and the top-level last stage must equal the
last entry. Unknown nesting or a caller-supplied summary rejects.

`transcript_sha256` is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/lifecycle-transcript/v2`, one NUL
byte, and the complete canonical transcript bytes. A transcript is an immutable
snapshot of one exact stable-loaded prefix, never an appendable or replaceable
file. Normal execution publishes the exact prefix snapshot required by the
post-teardown binding and, after terminal cleanup, the final pre-outcome
snapshot. Recovery first publishes/revalidates the exact classified-prefix
snapshot, retains its digest in the signed classification intent, and after
that intent is durable publishes the distinct final pre-outcome snapshot.

Publication uses exclusive no-follow creation of the fixed transcript staging
name, file fsync, `renameat2(RENAME_NOREPLACE)` to the exact content-addressed
name, parent-directory fsync, stable readback, canonical re-encoding, and
digest/name verification. That completed no-replace rename/fsync/readback is the
transcript commit; there is deliberately no mutable transcript head or separate
transcript commit marker. `EEXIST` permits only stable byte-for-byte
revalidation of the one exact existing final file; it never permits overwrite,
unlink, or replacement.
Staging presence, a second digest for one prefix, a file without its referenced
record or wire artifact, an unreferenced wire artifact, or an artifact beyond
the purported last ordinal is
retention-unconfirmed and permits no outcome. The terminal outcome and fixed
outcome commit must reference the exact published final transcript, making its
digest deterministic for normal execution, recovery, and later inspection.

The immutable transport-time transcript identity is
`lifecycle_dispatch_prefix_sha256`. It is computed only after stable readback of
the ordinal-zero root and ordinal-one request-intent artifacts and before the
application request is constructed. Its canonical preimage has exactly
`contract_version="phase6d-post-enrollment-graceful-stop-lifecycle-dispatch-prefix-v2"`,
`service="trusted-time-post-enrollment-graceful-stop-lifecycle-v2"`,
`status="lifecycle_dispatch_prefix_bound"`, `environment`,
`graceful_stop_operation_id`, `root_sha256`, `request_basis_sha256`,
`request_intent_sha256`,
`root_ordinal=0`, `root_stage="root_reserved"`, `request_intent_ordinal=1`,
`request_intent_stage="clean_stop_request_intent_retained"`, and
`request_intent_predecessor_sha256`. The last field equals `root_sha256`.
`request_basis_sha256` equals ordinal one's `arguments_sha256`.
Its digest is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/lifecycle-dispatch-prefix/v2`, one
NUL byte, and that complete canonical object.

This value is not caller supplied and does not hash a future mutable transcript.
It names the exact durable transcript prefix that exists at dispatch, avoiding
a request/transcript circularity. Every later transcript used by a result,
recovery classifier, binding, outcome, or commit must begin with exactly those
two entries, artifact digests, stages, ordinals, and predecessor relation; the
decoder recomputes the dispatch-prefix digest from those stable artifacts before
accepting the transcript. A different root, intent, first-two-entry projection,
or dispatch-prefix digest is a cross-lifecycle frame and rejects.

Canonical JSON is UTF-8, has lexicographically sorted keys, no insignificant
whitespace, and exactly one trailing newline. Duplicate keys at any depth,
floats, non-finite values, booleans as integers, unknown or missing fields,
noncanonical base64, integers outside their field bounds, excessive nesting,
and re-encoding inequality reject. Limits are 64 KiB for the root, 256 KiB per
progress, transcript, or outcome record, 262,144 bytes per signed wire
artifact, 64 lifecycle entries, depth 12, and
4,096 total JSON nodes. Filenames are at most 255 bytes. Limits are checked before decoding or
allocation proportional to attacker-declared sizes.

The terminal outcome field set is exactly `contract_version`, `service`,
`status`, `lifecycle_version`, `graceful_stop_operation_id`, `root_sha256`,
`ordinal`, `predecessor_sha256`, `final_stage`, `transcript_sha256`,
`reason_code`, `pre_effect_binding_sha256`,
`post_teardown_binding_sha256`, `volume_proof_sha256`,
`terminal_cleanup_sha256`, `stop_effects_confirmed`, `teardown_confirmed`,
`terminal_cleanup_confirmed`, `admission_started_boottime_ns`,
`operation_deadline_boottime_ns`, `commit_protocol_started_boottime_ns`,
`commit_publication_authorization_deadline_boottime_ns`,
`commit_authorized_boottime_ns`, and `created_at_utc`.
`status` is exactly `confirmed_success` or `recovery_required`. Confirmed success
requires non-null exact binding/proof/cleanup digests and all three booleans
true. Recovery-required requires all three booleans false; its nullable evidence
fields describe only the last durable prefix and grant no effect authority.
The admission-start and operation-deadline fields equal the root/admission and
must reproduce the checked 600-second addition before the candidate qualifies.
Both commit-window fields are built-in integers in `0..2^63-1`, and the
five-second addition is checked before use; overflow rejects. The publication-
authorization deadline is strictly after the protocol start.
For recovery-required, `commit_authorized_boottime_ns` is a non-null built-in
integer sampled before candidate publication. It is no earlier than
`commit_protocol_started_boottime_ns` and strictly earlier than
`commit_publication_authorization_deadline_boottime_ns`; the fixed marker
repeats it, so recovery can finalize that exact candidate after the window. For confirmed
success the candidate field is null because its final authorization check must
follow candidate stable readback and owner disposal; only the exact marker
staging/final preimage may carry the later non-null sample.
Confirmed success has ordinal 23, predecessor equal to the ordinal-22 record,
and `final_stage=terminal_cleanup_confirmed`. A recovery-required outcome has
the deterministic next ordinal and names only its exact last retained stage.

The fixed commit contains exactly `contract_version`, `service`, `status`,
`lifecycle_version`, `graceful_stop_operation_id`, `root_sha256`,
`outcome_sha256`, `outcome_status`, `transcript_sha256`,
`admission_started_boottime_ns`,
`commit_protocol_started_boottime_ns`,
`commit_publication_authorization_deadline_boottime_ns`,
`commit_authorized_boottime_ns`, `operation_deadline_boottime_ns`, and
`committed_at_utc`. Its status is `terminal_outcome_committed`. The protocol
start and publication-authorization deadline equal the candidate fields; the
deadline is exactly `commit_protocol_started_boottime_ns + 5_000_000_000` for
a recovery-required candidate and
`min(commit_protocol_started_boottime_ns + 5_000_000_000,
operation_deadline_boottime_ns)` for confirmed success.
`admission_started_boottime_ns` and `operation_deadline_boottime_ns` equal the
candidate, root, and consumed admission, and reproduce the checked 600-second
addition. `operation_deadline_boottime_ns` is the absolute
precommit authorization cutoff; `commit_authorized_boottime_ns` is the final
authoritative `CLOCK_BOOTTIME` sample, equals the recovery-required candidate's
non-null value, and replaces the confirmed-success candidate's null. The
protocol start must be less than or equal to that sample, which must be strictly
less than the publication-authorization deadline for both statuses and also
strictly less than the operation cutoff for confirmed success. A recovery-
required outcome may be classified after the operation cutoff but cannot
thereby become success. One exact committed outcome is terminal. A success and
recovery outcome cannot both qualify. A confirmed-success candidate or commit
is invalid unless its exact
predecessor is the durable terminal-cleanup result and its published transcript
ends at that result.

For confirmed success, ordinal twenty-three is one fixed commit procedure, not
a progress STORE followed by later authoritative work. After ordinal twenty-two
and final-transcript stable readback, it samples
`commit_protocol_started_boottime_ns`, derives the two bounded authorization
cutoffs above, and publishes and revalidates the one content-addressed outcome
candidate that binds those values. It prepares and validates one preallocated
canonical fixed-marker template whose only absent value is the authorization
sample. It then kernel-closes every transient
outcome/transcript file or directory descriptor, consumes the in-memory
candidate handle, proves a stable registry projection empty, and performs the
last authoritative check that `commit_authorized_boottime_ns` is strictly less
than both `commit_publication_authorization_deadline_boottime_ns` and
`operation_deadline_boottime_ns` and is no earlier than the protocol start.
Equality is expired. That check is the last
fallible success-classifying lifecycle work
before fixed-marker creation; the implementation enters the exclusive staging/
file-fsync/no-replace-rename/directory-fsync/stable-readback marker protocol
immediately afterward. Mechanically inserting the sampled integer into the
preallocated template and canonical-encoding the exact marker bytes are its
first steps; no intervening cleanup, lookup, allocation, validation, deadline
read, or policy decision is allowed.

The five-second commit value and 600-second whole-operation value are therefore
precommit authorization cutoffs, not claims that the marker's durable I/O
completes before either instant. Marker publication is the single authorized
post-cutoff lifecycle procedure. Its already-authorized bounded attempt may
either yield one stably authenticated fixed marker or
`outcome_commit_unconfirmed`; timeout, uncertain return, crash, or I/O failure
permits only revalidation/finalization of that same candidate/marker and never
an alternate outcome. A `CLOCK_BOOTTIME` sample after a stably authenticated
marker is telemetry only and cannot invalidate or reclassify it. At the
reported fixed commit boundary no repository owner retains a candidate or
artifact descriptor, so the only later descriptors are the already-empty
registry shell's own non-authoritative bookkeeping and the global lease FD
described below.

### Use a Linux pathname Unix-seqpacket transport with mutual signatures

The operational transport is Linux-only `AF_UNIX` `SOCK_SEQPACKET` with
`SOCK_CLOEXEC` and nonblocking I/O. TCP, abstract Unix sockets, stdout/stderr,
Docker exec, inherited anonymous socket pairs, and stream framing are not v2
transports.

The supervisor listens at the exact path:

```text
/run/autoquant/trusted-time/graceful-stop-v2/transport/supervisor.sock
```

`transport` is a dedicated root-created tmpfs mount with the literal options
`nodev,nosuid,noexec,size=64K`, owner/group `0:10001`, and mode `0770`. It is
projected read-write, with private mount propagation, at the same absolute path
into only the admitted supervisor container. The exact deployment must prove
that, among mount namespaces exposing this transport mount, only the fixed
supervisor process has effective or supplementary GID `10001`; the Chrony
container may retain the same numeric runtime identity but receives no
transport projection. No unrelated host process with GID `10001` may have the
host path reachable. A
`0:10001:0750` mount is invalid because UID/GID `10001:10001` cannot create the
listener there. World write/search, a read-only projection, another projection,
or any owner/group/mode/options drift rejects.

The supervisor creates the listener as effective UID/GID `10001:10001` under
umask `0177`; the socket must be a single-link `10001:10001:0600` socket inode.
Host root is the only connector and cleanup owner outside the container. The
directory mount identity, directory Stat9, socket Stat9/inode, named entry,
projection identity, and peer credentials are captured before use and
revalidated through close. Symlinks, replacement, a non-tmpfs mount,
link/entry ambiguity, an existing pathname at listener creation, or path,
permission, projection, or identity drift closes the channel.

The admitted topology deliberately retains Docker's private PID namespace; v2
does not add `pid: host`. It also requires the daemon's user-namespace remap to
be disabled and the supervisor to share the initial user namespace, so numeric
peer UID/GID values are stable. Peer admission is therefore asymmetric and
exact:

- from the host namespace, `SO_PEERCRED` must report UID/GID `10001:10001` and
  a positive host-visible PID. The host stable-reads that PID's start ticks,
  PID-namespace inode, `NSpid` terminal component, executable, cgroup/container
  membership, full container ID, and immutable image, then binds them to the
  signed supervisor process epoch; and
- from inside the supervisor's private PID namespace, the host connector is
  outside the visible namespace. `SO_PEERCRED` must therefore report UID/GID
  `0:0` and PID exactly zero. Any nonzero PID, mapped/remapped UID/GID, or attempt
  to resolve `/proc/0` rejects. The supervisor authenticates the host process
  epoch from the host-key signature and its exact canonical object; it does not
  claim an impossible container-side host PID/start-time observation.

Kernel credentials and pathname ownership remain defense in depth; neither is
accepted without the matching role-specific signature. This asymmetric rule
does not give the supervisor host PID or Docker authority and does not broaden
the current container's namespace or capabilities.

All framed fields are nonsecret. Confidentiality is intentionally not a
transport claim. Endpoint permissions limit observation, but the security
property is mutual origin authentication, integrity, channel binding, and
replay rejection through Ed25519 signatures. Adding encryption later would be a
new protocol version, not a silent v2 option.

The transport authority contract is
`phase6d-trusted-time-graceful-stop-transport-authority-v1`. One reviewed,
offline Ed25519 transport-root public key authenticates canonical, non-expiring
manifests. The exact manifest fields are `contract_version`, `service`,
`status`, `environment`, `generation`, `root_key_id`,
`predecessor_manifest_sha256`, `host_key_id`, `host_public_key_base64`,
`supervisor_key_id`, `supervisor_public_key_base64`, `recovery_key_id`,
`recovery_public_key_base64`, and `signature_ed25519_base64`. Status is
`transport_authority_manifest_issued`. One manifest contains exactly one host,
one supervisor, and one recovery-classifier public key for one environment and
positive generation. The three roles never share a private key. The anchor
signer, start operator key, and stop operator key are separate domains and are
not transport keys.

The manifest signature input is the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/transport-authority/v1`, one NUL
byte, and the canonical fields other than `signature_ed25519_base64`. The exact
root public key is a canonical 32-byte Ed25519 public key, and `root_key_id`
must match its reviewed identity.

Manifests have no UTC validity or expiry field. Selection and denial are
defined only by root-signed contract
`phase6d-trusted-time-graceful-stop-transport-authority-selection-v1` at exact
installed path
`/opt/autoquant/trusted-time/authorities/graceful-stop-v2/selection.json`.
Its exact fields are `contract_version`, `service`, `status`, `environment`,
`selection_sequence`, `disposition`, `selected_manifest_sha256`,
`selected_generation`, `recovery_manifest_sha256`,
`predecessor_selection_sha256`, `reason_code`, and
`signature_ed25519_base64`. `disposition` is `generation_selected` or
`new_roots_denied`; `reason_code` is `initial`, `rotation`,
`suspected_compromise`, or `administrative_hold`. Selected manifest/generation
are non-null only for `generation_selected`. `recovery_manifest_sha256` is
either the exact manifest permitted to classify an already-retained root or
null, which makes recovery read-only. Status is
`transport_authority_selection_recorded`. Selection records do not expire. The
selection signature input is the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/transport-authority-selection/v1`,
one NUL byte, and the canonical fields other than
`signature_ed25519_base64`.

Every manifest is retained content-addressed below
`/opt/autoquant/trusted-time/authorities/graceful-stop-v2/`, and the exact root
public key is installed at
`/opt/autoquant/trusted-time/authorities/graceful-stop-v2/root-ed25519.pub`.
The immutable deployment admits exactly one stable selection file and complete
predecessor chains. With the lifecycle root absent, normal admission accepts
only `generation_selected` and its exact selected manifest. With a root present,
historical verification uses only the manifest digest pinned in that root;
recovery signing additionally requires the selection's
`recovery_manifest_sha256` to equal it. A `new_roots_denied` selection is the
only v1 revocation/administrative-hold mechanism: it forbids every new root and
may separately allow or deny recovery signing. There is no undefined
"expired", "current", or ambient-time revocation predicate.

The transport frame contract is
`phase6d-trusted-time-graceful-stop-transport-envelope-v2`. Its unsigned field
set is exactly `contract_version`, `service`, `protocol_version`, `environment`,
`direction`, `frame_type`, `payload_contract_version`, `key_generation`,
`signing_key_id`, `boot_epoch_sha256`, `host_process_epoch_sha256`,
`supervisor_process_epoch_sha256`, `channel_id`,
`lifecycle_dispatch_prefix_sha256`, `message_counter`,
`deadline_boottime_ns`, `payload_sha256`, and `payload_base64`. The encoded
envelope adds only `signature_ed25519_base64`.

`service` is `trusted-time-graceful-stop-transport-v2` and
`protocol_version` is integer two.
`frame_type` is exactly `clean_stop_request`, `clean_stop_result`, or
`clean_stop_error`; direction, signer role, payload contract, and counter must
match that choice. Request direction/counter is `host_to_supervisor`/two;
result and error direction/counter are `supervisor_to_host`/one.
`payload_base64` is padded RFC 4648 base64 with no whitespace
or alternate alphabet. A 32-byte challenge encodes to 44 characters and a
64-byte Ed25519 signature encodes to 88 characters; re-encoding inequality
rejects.

The Ed25519 signature input is the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2`, one NUL
byte, and the complete canonical unsigned envelope. Thus every request,
result, and error signature binds its direction, schema, environment, key
generation and role, channel, boot and both process epochs, exact durable
ordinal-zero/one lifecycle dispatch prefix, counter, deadline, and the SHA-256
and complete canonical bytes of its payload. A verified digest without the
verified full payload is insufficient.

One seqpacket contains one complete canonical message and is at most exactly
262,144 bytes. For an application payload of `P` bytes, let `O` be the exact
length of the canonical signed envelope with the actual fixed-width fields and
signature but an empty `payload_base64` string. The encoder must prove
`O <= 8,192`; the exact encoded length is
`O + 4 * ceil(P / 3)`. Payload ceilings are 65,536 bytes for a request,
180,224 bytes for a result, and 32,768 bytes for an error. Their worst-case
envelope lengths are therefore at most 95,576, 248,492, and 51,884 bytes,
respectively, all below the packet ceiling. No 192-KiB result is allowed: its
base64 alone would consume the entire packet and leave no envelope room.

The receiver allocates the fixed 262,145-byte detection buffer, calls
`recvmsg` once, and rejects equality above the 262,144-byte bound,
`MSG_TRUNC`, `MSG_CTRUNC`, continuation, ancillary data, unexpected credentials,
multiple messages in one packet, or a packet after the allowed terminal frame.
It checks the encoded limit, exact envelope overhead, base64 decoded-length
formula, and frame-specific payload ceiling before allocating or decoding the
payload. Every boundary at `limit - 1`, `limit`, and `limit + 1`, plus maximum
base64 padding, is a required vector.

### Keep endpoint keys ephemeral at rest and rotate without overlap

Private transport and recovery credentials exist only in three named,
root-created tmpfs
mounts:

```text
/run/autoquant/trusted-time/graceful-stop-v2/host-secrets
/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets
/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets
```

All three mounts use literal `nodev,nosuid,noexec,size=64K`. Host and recovery
mounts are `0:0:0700`. The supervisor mount is `0:10001:0730` and is projected
read-write with private propagation at the same absolute path into only the
admitted supervisor container; group write/search is required so its native
owner can unlink the loaded inode, while lack of group read prevents directory
enumeration. The host raw 32-byte seed is `0:0:0400`. The supervisor raw seed is
`10001:10001:0400`. It is not a read-only single-file bind mount: such a bind
would retain a readable key inode after host-path unlink. The dedicated tmpfs
projection lets the supervisor stable-read and exact-inode-unlink the one file
so both namespace paths disappear before the signer is exposed. The recovery
raw seed is `0:0:0400` and available only to the recovery-classifier fixed
launcher. Exact target names are
`host-secrets/host-ed25519.raw`,
`supervisor-secrets/supervisor-ed25519.raw`, and
`recovery-secrets/recovery-ed25519.raw`.

The sole persistent credential sources are TPM2-bound `systemd-creds` encrypted
blobs at exact paths
`/etc/credstore.encrypted/autoquant-trusted-time-graceful-stop-v2-host-g<generation:08d>.cred`,
`/etc/credstore.encrypted/autoquant-trusted-time-graceful-stop-v2-supervisor-g<generation:08d>.cred`,
and
`/etc/credstore.encrypted/autoquant-trusted-time-graceful-stop-v2-recovery-g<generation:08d>.cred`,
owned by root and mode `0600`. A root-owned provisioning unit uses the pinned
`/usr/bin/systemd-creds decrypt --name=<literal-role-name> <exact-blob> -`
profile, but never `LoadCredentialEncrypted`: before exec, its fixed native
parent exclusively opens the exact no-follow target in the corresponding named
tmpfs, applies the role-specific owner/mode above, and duplicates that same
inode onto child descriptor one. Descriptor one is not a terminal, pipe,
journal, or ambient standard stream; it is the sole preopened target inode, and
every other writable descriptor is closed. After the child exits zero, the
parent stable-reads that inode and requires exactly 32 bytes, unchanged
device/inode/owner/mode, no second link, and a matching manifest public key
before starting the signer, then explicitly zeroizes its derivation buffer. No
systemd credential-directory plaintext file is created. Failure exact-inode-
unlinks the target and destroys every native buffer.

The three unit/name pairs are exactly
`autoquant-trusted-time-graceful-stop-v2-host-provision.service` /
`autoquant-trusted-time-graceful-stop-v2-host`,
`autoquant-trusted-time-graceful-stop-v2-supervisor-provision.service` /
`autoquant-trusted-time-graceful-stop-v2-supervisor`, and
`autoquant-trusted-time-graceful-stop-v2-recovery-provision.service` /
`autoquant-trusted-time-graceful-stop-v2-recovery`. Each unit has one literal
blob-path template, one literal target path, and no caller-supplied role, output,
generation, or extra argument; it substitutes only the already-selected
eight-digit generation into its own blob filename before exec.

Decrypted bytes therefore exist only in one of the three named tmpfs mounts;
they never enter an environment variable, argv, Python, an ambient stdout/stderr
sink, or an ordinary filesystem path. The named target is stable-identity
checked and exact-inode-unlinked as soon as the native signer owns the seed.
Private bytes in a repository, image layer, log, lifecycle record, general
artifact root, persistent volume, or ordinary disk file are forbidden.

Each endpoint stable-reads its exact no-follow single-link credential into a
native fixed-size signer owner. The owner requires `mlock`, marks memory
`MADV_DONTDUMP|MADV_WIPEONFORK`, never returns raw private bytes to Python, and
unlinks the exact loaded credential inode immediately after public-key
derivation matches the signed manifest. Any `mlock`, unlink, ownership,
permission, path, public-key, or inode revalidation failure closes the endpoint.
On every terminal, failure, recovery, fork-child, or cleanup path, the owner
calls an admitted explicit zeroization primitive before `munlock` and close.
Process death relies on kernel address-space destruction; the already-unlinked
tmpfs file cannot become a restart credential.

Exactly one key generation is selected for new roots. The manifest's
`predecessor_manifest_sha256` is null only for generation one, and every later
generation increments by one and names its exact predecessor. The selection
sequence likewise begins at one and increments by one. Unknown generations,
skipped predecessors, duplicate selection heads, simultaneous selected
generations, role/key reuse, selection/manifest mismatch, or any root/signature
mismatch fail closed.

Rotation is permitted only while the permanent lifecycle root is positively
absent, no listener or channel exists, and the global launcher lock is held.
The next generation must be exactly the signed selected generation plus one,
reference the exact
selected manifest digest, replace all three role keys, and be selected by the
next root-signed selection record in one reviewed immutable deployment. There
is no grace window accepting both generations. Once a root exists, host and
supervisor credential provisioning is forbidden, even for its pinned
generation. Its manifest digest and public keys remain the only keys accepted
to authenticate retained frames.

After a crash with a v2 root, only the recovery unit may reload a private seed.
It must select the encrypted recovery blob whose generation equals the root,
require the root-pinned manifest digest to equal
`recovery_manifest_sha256` in the one stable installed selection record, derive the exact
manifest recovery public key, and load no host or supervisor blob. A null or
different recovery selection permits read-only inspection only. The recovery
native signer exposes solely the recovery-classification signature domain; its
type, fixed-launcher target, imports, seccomp profile, and architecture guard
cannot create a transport envelope, open/connect a transport socket, or reach a
Docker API. Root-authority rotation requires a new ADR and reviewed trust-root
version; it cannot be expressed as an ordinary key-generation update.

### Bind boot, processes, challenges, counters, and numeric deadlines

V2 supports the admitted Linux deployment only. It reads
`/proc/sys/kernel/random/boot_id` twice through the stable native file boundary
and requires one canonical lowercase UUID. `boot_epoch_sha256` is SHA-256 over
the domain `AutoQuantTrader/trusted-time/graceful-stop/boot/v2`, a NUL byte, and
the UUID ASCII bytes.

The process-epoch contract is
`phase6d-trusted-time-graceful-stop-process-epoch-v2`, service
`trusted-time-graceful-stop-transport-v2`, status `process_epoch_bound`. Its
canonical object has exactly `contract_version`, `service`, `status`,
`environment`, `role`, `boot_epoch_sha256`, `pid`, `start_time_ticks`,
`pid_namespace_inode`, `executable_path`, `executable_sha256`,
`import_manifest_sha256`, `process_nonce_base64`, `container_id`, and
`image_id`. `role` is `host` or `supervisor`; `pid`, start ticks, and namespace
inode are exact built-in integers in `1..2^63-1`; the executable path is the
absolute manifest-pinned path and at most 255 UTF-8 bytes; and the nonce is
exactly 32 bytes from blocking `getrandom`. Host container/image fields are
null. The supervisor `container_id` is exactly 64 lowercase hexadecimal
characters and `image_id` is literal `sha256:` plus 64 lowercase hexadecimal
characters; its PID/start/namespace values come from namespace-local
`getpid()`, `/proc/self/stat` field 22, and `/proc/self/ns/pid`. The process
epoch is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/process-epoch/v2`, one NUL byte,
and that complete canonical object. PID equality alone is never an identity.

Peer credentials use one canonical object with exactly `observer_role`,
`peer_uid`, `peer_gid`, `peer_pid_disposition`, `peer_pid`,
`peer_start_time_ticks`, `peer_pid_namespace_inode`, `peer_namespace_pid`,
`peer_container_id`, `peer_image_id`, and `peer_executable_sha256`. The host
observation uses disposition `host_visible_supervisor`, the positive values and
exact identities described above. The supervisor observation uses disposition
`host_outside_private_pid_namespace`, UID/GID zero, PID integer zero, and null
for every unobservable PID/process/container field. Its digest is SHA-256 over
the ASCII domain `AutoQuantTrader/trusted-time/graceful-stop/peer-credential/v2`,
one NUL byte, and the canonical object. Each endpoint also hashes an exact
socket-view object with fields `observer_role`, `absolute_path`, `mount_id`,
`mount_parent_id`, `mount_major_minor`, `mount_root`, `mount_options`,
`directory_device`, `directory_inode`, `directory_uid`, `directory_gid`,
`directory_mode`, `socket_device`, `socket_inode`, `socket_uid`, `socket_gid`,
and `socket_mode`. Host and supervisor use the complete respective ASCII domains
`AutoQuantTrader/trusted-time/graceful-stop/host-socket-identity/v2` and
`AutoQuantTrader/trusted-time/graceful-stop/supervisor-socket-identity/v2`, one
NUL byte, and that canonical object. Their digests remain separate because
mount-namespace IDs need not match.

The host must prove the signed supervisor epoch's namespace-local PID equals
the terminal `NSpid` component in its peer observation and that start ticks,
PID-namespace inode, executable/import digests, container ID, and image ID all
equal the stable host `/proc`/Docker/deployment profile. The supervisor cannot
make the symmetric kernel-PID proof; it instead requires the host-key signature,
same boot digest, positive PID/start/namespace fields, fresh process nonce, and
the exact immutable host executable/import profile admitted by its fixed image.
Any mismatch is endpoint substitution, not a weaker observation mode.

In these objects, every SHA-256 field is exactly 64 lowercase hexadecimal
characters; UID/GID values are built-in integers in `0..2^32-2`; device,
inode, mount-ID, PID, and start-time values are built-in integers in
`0..2^63-1` with zero allowed only where the field rule above says so; and mode
is the exact permission integer without file-type bits. `mount_options` is a
lexicographically sorted, duplicate-free list of the literal option strings
reported by the stable native mount reader. A process or peer field described
as unobservable is JSON null, never zero or an empty string. These exact types
and null rules are part of each domain preimage.

The host and supervisor each obtain another independent 32-byte challenge from
blocking `getrandom`. The handshake is exactly three signed seqpackets; none is
an application envelope:

1. Host contract `phase6d-trusted-time-graceful-stop-host-hello-v2`, status
   `host_hello_offered`, has exactly `contract_version`, `service`, `status`,
   `protocol_version`, `environment`, `direction`, `message_counter`,
   `graceful_stop_operation_id`, `transport_authority_manifest_sha256`,
   `key_generation`, `host_key_id`, `expected_supervisor_key_id`,
   `boot_epoch_sha256`, `host_process_epoch`, `host_process_epoch_sha256`,
   `host_challenge_base64`, `host_socket_identity_sha256`,
   `host_peer_credential_sha256`, and `handshake_deadline_boottime_ns`; encoded
   bytes add only `signature_ed25519_base64`. Direction is `host_to_supervisor`
   and counter is zero.
2. Supervisor contract
   `phase6d-trusted-time-graceful-stop-supervisor-hello-v2`, status
   `supervisor_hello_accepted`, has exactly `contract_version`, `service`,
   `status`, `protocol_version`, `environment`, `direction`, `message_counter`,
   `graceful_stop_operation_id`, `transport_authority_manifest_sha256`,
   `key_generation`, `host_key_id`, `supervisor_key_id`, `boot_epoch_sha256`,
   `host_hello_sha256`, `host_process_epoch_sha256`,
   `supervisor_process_epoch`, `supervisor_process_epoch_sha256`,
   `host_challenge_base64`, `supervisor_challenge_base64`,
   `host_socket_identity_sha256`, `supervisor_socket_identity_sha256`,
   `host_peer_credential_sha256`, `supervisor_peer_credential_sha256`,
   `channel_id`, and `handshake_deadline_boottime_ns`; encoded bytes add only
   `signature_ed25519_base64`.
   Direction is `supervisor_to_host` and counter is zero.
3. Host contract
   `phase6d-trusted-time-graceful-stop-host-channel-confirmation-v2`, status
   `host_channel_confirmed`, has exactly `contract_version`, `service`, `status`,
   `protocol_version`, `environment`, `direction`, `message_counter`,
   `graceful_stop_operation_id`, `transport_authority_manifest_sha256`,
   `key_generation`, `host_key_id`, `supervisor_key_id`, `boot_epoch_sha256`,
   `host_hello_sha256`, `supervisor_hello_sha256`,
   `host_process_epoch_sha256`, `supervisor_process_epoch_sha256`, `channel_id`,
   and `handshake_deadline_boottime_ns`; encoded bytes add only
   `signature_ed25519_base64`.
   Direction is `host_to_supervisor` and counter is one.

For all three, `service` is `trusted-time-graceful-stop-transport-v2` and
`protocol_version` is integer two. The signature domains are respectively
`AutoQuantTrader/trusted-time/graceful-stop/host-hello/v2`,
`AutoQuantTrader/trusted-time/graceful-stop/supervisor-hello/v2`, and
`AutoQuantTrader/trusted-time/graceful-stop/host-channel-confirmation/v2`, each
followed by one NUL byte and the complete canonical unsigned object.
`host_hello_sha256`
and `supervisor_hello_sha256` are SHA-256 of the corresponding complete
canonical signed bytes. Host hello, supervisor hello, and confirmation are
bounded to exactly 8,192, 12,288, and 8,192 encoded bytes. The common canonical
decoder rules and packet/truncation checks apply before signature verification.
Every digest and key-generation field uses the exact representation above;
key generation and both deadline/counter fields are built-in integers in
`0..2^63-1`, with generation positive; each challenge is padded canonical base64
of exactly 32 decoded bytes; and operation/key IDs are nonempty canonical ASCII
strings of at most 128 bytes. An unsigned field may not be omitted, inferred,
or represented by a sibling contract's value.

`channel_id` is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/channel/v2`, one NUL byte, and a
canonical object with exactly `contract_version`, `service`,
`protocol_version`, `environment`, `graceful_stop_operation_id`,
`transport_authority_manifest_sha256`, `key_generation`, `host_key_id`,
`supervisor_key_id`, `boot_epoch_sha256`, `host_process_epoch_sha256`,
`supervisor_process_epoch_sha256`, `host_hello_sha256`,
`host_challenge_base64`, `supervisor_challenge_base64`,
`host_socket_identity_sha256`, `supervisor_socket_identity_sha256`,
`host_peer_credential_sha256`, `supervisor_peer_credential_sha256`, and
`handshake_deadline_boottime_ns`.
The supervisor computes it before signing its hello; the host recomputes it
before signing confirmation; the supervisor recomputes confirmation. No field
is inferred from arrival order or local defaults.

Each direction owns one unsigned 64-bit monotonic counter. Host hello is zero,
host confirmation is one, and the sole host operation request is two.
Supervisor hello is zero, and the sole supervisor operation result or error is
one. No retransmission, duplicate, gap, reuse, rollback, wrap, or additional
frame is accepted. Counter state and the channel digest are registered before a
message is exposed; after root reservation the channel digest and expected
request/result counters are also bound into durable intent and result records.

A crash cannot reset a counter into an accepted channel. A restarted process
has a different process epoch and fresh challenge, so old frames fail the
signature-bound channel. Before root reservation a new channel is allowed only
through a fresh complete admission; no operation frame has yet been sent. After
root reservation the permanent root blocks every new normal channel, and only
the distinct recovery-classifier contract may inspect or terminally classify
the retained prefix.

All acceptance time uses Linux `CLOCK_BOOTTIME`. Numeric budgets are:

- 5 seconds to acquire the global launcher lock;
- 5 seconds total for connect and mutual handshake;
- 2 seconds for each complete seqpacket send or receive;
- 120 seconds from durable request intent to clean-stop result/error receipt;
- 120 seconds for each ADR-0109 pre-effect or post-teardown observation;
- 30 seconds for each exact container stop;
- 15 seconds for each exact container or network removal;
- 10 seconds for the complete two-volume preservation proof;
- 5 seconds from each durable record/transcript/outcome publication procedure's
  start through its final prepublication authorization check; and
- 600 seconds from the exact `admission_started_boottime_ns` sample through the
  ordinal-23 final precommit authorization check.

Every normal-path prepublication deadline is the minimum of its stated
authorization window and the absolute whole-operation authorization cutoff.
That cutoff is always the checked exact sum
`admission_started_boottime_ns + 600_000_000_000`; a supplied, recomputed, or
recovered alternative rejects.
The separately admitted recovery classifier has a fresh five-second
publication-authorization window and may classify after the normal operation
cutoff, but may never publish a new confirmed-success candidate. Both endpoints bind the same absolute boot-time
request/result deadlines. Equality is expired. Clock read failure, regression,
wrong clock ID, different boot epoch, over-budget cleanup, or deadline equality
fails closed. Before the authorization check, the publisher completes every
success-relevant prerequisite and prepares a bounded exact template/basis. If
the artifact carries the authorization sample, mechanically inserting that
sample into a preallocated template and canonical-encoding the exact bytes are
the first steps of the already-authorized fixed publication protocol; otherwise
the bytes are already canonical before the check. No policy, validation,
cleanup, lookup, or allocation may intervene. The protocol may cross its
authorization cutoff; it either produces one stably authenticated immutable
artifact or an ambiguous return, and no postpublication clock read can
reclassify the artifact.
Before possible root creation failure means no attempt; afterward it means
recovery-required until outcome-candidate publication may have begun. From that
point it is `outcome_commit_unconfirmed` and permits only the exact candidate/
marker recovery rules above. The ordinal-23 marker uses the exact dual-cutoff
procedure above. No success-relevant cleanup or deadline check remains after
that commit, and post-commit disposal does not consult or extend either
authorization cutoff.

### Freeze independent request, result, and error schemas

The v2 application family does not import, call, decode, wrap, or construct an
ADR-0110/0111 v1 type. Shared field meanings may be reimplemented from primitive
sources, but no v1 object, bytes, digest adapter, process seal, bridge identity,
or host composite may enter the v2 graph.

The request contract is
`phase6d-trusted-time-head-anchor-clean-stop-request-v2`, service
`trusted-time-head-anchor-clean-stop-v2`, status
`operation_bound_clean_stop_requested`. Its exact fields are:

- `contract_version`, `service`, `status`, and `environment`;
- `graceful_stop_operation_id`, `graceful_stop_target_sha256`,
  `graceful_stop_decision_v1_sha256`,
  `historical_decision_receipt_sha256`, and
  `graceful_stop_operator_attestation_envelope_sha256`;
- `lifecycle_root_sha256`, `request_basis_sha256`,
  `request_intent_sha256`, `admission_sha256`,
  `lifecycle_dispatch_prefix_sha256`, `topology_sha256`,
  `topology_lease_sha256`, and `trusted_head_sha256`;
- `supervisor_container_id`, `channel_id`, `boot_epoch_sha256`,
  `host_process_epoch_sha256`, and `supervisor_process_epoch_sha256`;
- `checkpoint_reason`, `exact_new_record_required`,
  `clean_stop_result_deadline_boottime_ns`, `transport_cleanup_required`,
  `transport_cleanup_deadline_boottime_ns`, `admission_started_boottime_ns`,
  and `operation_deadline_boottime_ns`.

The final request copies every non-derived primitive from the exact ordinal-one
basis, replaces only its basis contract/status with the final request contract/
status above, and adds `request_basis_sha256`, `request_intent_sha256`, and the
derived `lifecycle_dispatch_prefix_sha256`. No final-request byte or digest is
an ordinal-one input. The reason is exactly `clean_stop`; `exact_new_record_required` and
`transport_cleanup_required` are true. The cleanup deadline is exactly
`min(clean_stop_result_deadline_boottime_ns + 5_000_000_000,
operation_deadline_boottime_ns)` and admission rejects unless it is strictly
after the result deadline. The already-durable signed request therefore directs
the supervisor to send its one result/error and immediately execute the fixed
quiescence sequence without waiting for another frame. The request is at most
64 KiB. Its `request_basis_sha256` equals ordinal one's `arguments_sha256`.
Its `lifecycle_dispatch_prefix_sha256` is the exact value recomputed from its
stable root and request-intent artifacts above and equals the signed
transport envelope field; the supervisor rejects any disagreement before
constructing a typed request. Its admission-start and operation-deadline values
equal the request basis, ordinal-one admission evidence, lifecycle root, and
consumed admission projection and must reproduce the checked 600-second sum.

The result contract is
`phase6d-trusted-time-head-anchor-clean-stop-result-v2`, with status
`exact_operation_bound_new_record_clean_stop_correlated_unqualified`. Its exact
top-level fields are `contract_version`, `service`, `status`, `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, `admission_sha256`,
`lifecycle_dispatch_prefix_sha256`, `channel_id`, `boot_epoch_sha256`,
`host_process_epoch_sha256`,
`supervisor_process_epoch_sha256`, `supervisor_container_id`,
`operation_bound_request`, `request_sha256`, `terminal_projection`,
`terminal_projection_sha256`,
`supervisor_transport_cleanup_commitment`,
`supervisor_transport_cleanup_commitment_sha256`,
`result_completed_boottime_ns`, `transport_cleanup_deadline_boottime_ns`, and
`operation_deadline_boottime_ns`.

`operation_bound_request` is the complete request object above, not base64,
bytes, or a partial projection. `terminal_projection` has exactly these nested
fields:

- `request_sequence`, `request_scheduled_monotonic_ns`, `anchor_sequence`,
  `checkpoint_reason`, `confirmed_anchor_count`, `local_transition_count`, and
  `confirmed_anchor_local_transition_ordinal`;
- `predecessor_anchor_sha256`, `current_host_head_sha256`,
  `current_anchor_sha256`, and `current_anchor_semantic_sha256`;
- `receipt_observed_at_utc`, `full_audit_completed`, and
  `prior_pending_intent_recovered`;
- `uploaded_anchor_count` and `idempotent_duplicate_count`; and
- `current_anchor_intent_semantic_sha256`,
  `current_candidate_remote_readback_sha256`,
  `current_receipt_semantic_sha256`, and
  `clean_stop_terminal_result_semantic_sha256`.

All sequence/count/ordinal values except the scheduled instant are exact
built-in integers in `1..2^63-1`; the scheduled instant is in `0..2^63-1`.
Every digest is 64 lowercase hexadecimal characters. The receipt instant is
canonical UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`; the two audit/recovery facts are
exact booleans. `checkpoint_reason` is `clean_stop`, anchor sequence equals
confirmed count and is at least three, terminal ordinal equals local count and
is at least anchor sequence, each upload/duplicate count is zero or one and the
sum is one, and `current_candidate_remote_readback_sha256` equals
`current_anchor_sha256`.

`request_sha256` is SHA-256 of the complete canonical request bytes. Every
duplicated operation/root/request-basis/request-intent/admission/dispatch-
prefix/channel/epoch/container/deadline field must equal
`operation_bound_request`; the result envelope's
dispatch-prefix field must equal both payload occurrences, and re-encoding must
reproduce the request bytes exactly.
The nested `clean_stop_terminal_result_semantic_sha256` is independently
recomputed from the first nineteen ADR-0108 primitive fields under ADR 0108's
exact canonical semantic construction without importing or accepting its v1
object. `terminal_projection_sha256` is separately SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/terminal-projection/v2`, one NUL
byte, and the complete twenty-field nested object. Completion must be strictly
before both result and operation deadlines. Unknown top-level or nested fields,
wrong built-in types, null substitution, digest disagreement, or correlation
drift rejects.

`supervisor_transport_cleanup_commitment` is the complete canonical contract
`phase6d-trusted-time-graceful-stop-supervisor-transport-cleanup-commitment-v2`,
service `trusted-time-graceful-stop-transport-v2`, status
`supervisor_transport_cleanup_committed`. It has exactly
`contract_version`, `service`, `status`, `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, `admission_sha256`,
`channel_id`, `boot_epoch_sha256`, `supervisor_process_epoch_sha256`,
`supervisor_container_id`, `transport_authority_manifest_sha256`,
`key_generation`, `supervisor_key_id`, `supervisor_socket_identity_sha256`,
`supervisor_peer_credential_sha256`, `listener_path`,
`listener_path_device`, `listener_path_inode`, `listener_fd_socket_inode`,
`accepted_fd_socket_inode`, `raw_key_path`, `raw_key_device`, `raw_key_inode`,
`supervisor_challenge_sha256`,
`supervisor_process_nonce_sha256`, and `cleanup_deadline_boottime_ns`.
Paths are the exact absolute paths frozen above; device/inode values are
positive built-in integers in `1..2^63-1`; the challenge and process-nonce
digests hash the respective 32 decoded bytes; and the cleanup deadline is
strictly after result/error completion and no later than the operation deadline.
Every correlator equals the root, channel, handshake, process epoch, manifest,
signed-request cleanup deadline, and stable-loaded custody/socket identities
already held by both endpoints.
Its digest is SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/supervisor-transport-cleanup-commitment/v2`,
one NUL byte, and the complete nested object. That value must equal
`supervisor_transport_cleanup_commitment_sha256`; a digest without the nested
object, or an object the host cannot independently re-encode and correlate,
rejects.

Before request dispatch, host root uses the already-bound positive supervisor
host PID for a bounded, double-stable read of at most 1,024 `/proc/<pid>/fd`
entries and `/proc/net/unix`. It must correlate the path inode, listener socket
object inode, and exactly one accepted socket object inode in the signed
commitment to the same process epoch and channel; an unstable table, extra
candidate, or missing mapping rejects. After terminal EOF it repeats that
stable read and requires both socket object inodes absent, the path entry absent,
and the process epoch unchanged. This is the authenticated host observation
behind `listener_closed` and `socket_unlinked`; pathname absence alone is not
treated as descriptor closure.

The FD-table projection has exactly `supervisor_process_epoch_sha256`,
`fd_count`, and sorted `entries`; each entry has exactly `fd_number`,
`target_kind`, and `socket_inode`, where kind is `socket` with a positive inode
or `other` with null. Its digest uses the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/supervisor-fd-table/v2`, one NUL
byte, and the complete canonical projection. The fixed native `/proc/net/unix`
parser accepts at most 4 MiB/65,536 rows, the exact kernel header/column grammar,
hexadecimal numeric fields without overflow, and exactly one listening
`SOCK_SEQPACKET` row whose pathname bytes are the fixed socket path and whose
socket-object inode equals the commitment. Unknown grammar, a duplicate path,
or table drift rejects rather than being ignored.

The result payload is at most 180,224 bytes so its signed base64 envelope fits
the mathematical bound above. Its only positive fact is structural exact-
request/new-record correlation plus a signed cleanup commitment; neither is
cleanup completion or effect authority. An effect remains forbidden until the
transport cleanup result and separate pre-effect binding are both durable.

The error contract is
`phase6d-trusted-time-head-anchor-clean-stop-error-v2`, status
`operation_bound_clean_stop_failed_unqualified`. Its exact fields are
`contract_version`, `service`, `status`, `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, `request_sha256`,
`admission_sha256`, `lifecycle_dispatch_prefix_sha256`, `channel_id`,
`boot_epoch_sha256`,
`host_process_epoch_sha256`, `supervisor_process_epoch_sha256`,
`supervisor_container_id`, `error_code`, `failure_boundary`,
`call_may_have_occurred`, `retryable`, `observed_boottime_ns`,
`supervisor_transport_cleanup_commitment`,
`supervisor_transport_cleanup_commitment_sha256`,
`transport_cleanup_deadline_boottime_ns`, and
`operation_deadline_boottime_ns`. `retryable` is always false. The nested
cleanup object/digest use the exact result schema and must repeat the request's
fixed cleanup deadline, so both signed terminal-frame variants authenticate the
same mandatory quiescence plan.

The result and error service is exactly
`trusted-time-head-anchor-clean-stop-v2`, matching the request.

`error_code` is one of `request_expired`, `worker_busy`, `selection_failed`,
`clean_stop_failed`, or `result_unavailable`. `failure_boundary` is
`before_selection`, `during_or_after_selection`, or `unknown`. These values are diagnostic only.
Because the root and intent are already durable before dispatch, every valid
error still advances only to recovery-required. An unauthenticated, invalid,
late, missing, or conflicting error is also recovery-required and supplies no
diagnostic fact.

A signed error may be constructed only after the complete canonical request and
all root/admission/channel correlators have decoded and rebound. Schema,
signature, or binding rejection before that point closes/quiesces without an
application error frame; it never guesses correlators from a partial payload.

The error payload is at most 32,768 bytes. Both booleans are exact built-in
booleans; boottime values are built-in integers in `0..2^63-1`, observation is
strictly before the operation deadline, and every duplicated correlator equals
the durable root/request intent, including the recomputed lifecycle dispatch
prefix, and signed envelope. The error, result, and
request payload contracts each reject bytes for either sibling contract before
constructing any typed object.

V1 and v2 decoders reject each other's contract strings and bytes. The v2
module dependency graph statically excludes the ADR-0110 lifecycle module and
ADR-0111 low-level and host bridge modules. There is no common version-guessing
decoder.

### Choose the additive ADR-0112 v2-bound consumed-snapshot handoff

ADR 0116 offered two historical-receipt choices. V2 chooses the additive
private ADR-0112 seam, not an independent duplicate loader.

The decision-artifact module will add a separately named private v2 consumer
and private immutable primitive snapshot. It will use the same stable loader,
fresh historical-source reconstruction, pending-registration consumption,
active-registration consumption, and complete source comparison already
reviewed by ADR 0112, but bind the result to a new lifecycle-v2 bridge
capability, exact operation, exact admission identity, origin PID, exact Thread,
and channel. It must not call or accept the current ADR-0112-to-ADR-0111 v1
consumer, bridge identity, request, lifecycle receipts, or host binder.

The existing public loaded-wrapper contract and every v1 private seam retain
their current meaning and callers. The new consumer is one shot, burns pending
and active state on every terminal path, returns only primitive immutable
source facts, and is reachable only from the v2 admission builder. This choice
keeps one historical source-authentication implementation while creating a
strictly separate capability domain. A duplicate receipt loader would create a
second implementation whose source graph and drift rules could diverge.

### Define one same-lock admission and lock order

The controller acquires the existing exact native launcher lock at
`<ignored-root>/trusted-time/trusted-time-launch.lock` with the five-second
`CLOCK_BOOTTIME` budget. It owns one opaque native lease; it never reopens the
path or treats an integer descriptor, path, or boolean as the lease. The lease
is held from before channel preflight through transport quiescence, effects,
terminal cleanup, final transcript, and the exact fixed outcome commit. After
that terminal commit, already-empty registry invalidation and descriptor close
are non-authoritative disposal outside the lifecycle and deadline; the process
does not run another lifecycle transition while holding or releasing them.

Immediately after lock acquisition returns one stably revalidated lease, the
fixed native owner validates the origin PID, exact Thread, fork epoch, boot
epoch, and exact `CLOCK_BOOTTIME` identity/readability. It then takes exactly
one `clock_gettime(CLOCK_BOOTTIME)` sample; that syscall return is the precise
admission-start boundary and becomes `admission_started_boottime_ns`. The sample
precedes root-absence lookup, executable/import or authority-manifest reads,
private-key loading, endpoint/socket/channel work, stop-authority, topology,
Docker, provider/database, trusted-head, or historical-receipt reads, and any
admission/root construction. The native owner requires a built-in integer in
`0..2^63-1`: `tv_sec` is nonnegative, `tv_nsec` is in `0..999_999_999`,
and checked multiply/add of `tv_sec * 1_000_000_000 + tv_nsec` produces that
integer without overflow. It then proves the value is at most
`2^63-1 - 600_000_000_000`, and performs one checked addition to derive exactly
`operation_deadline_boottime_ns` as the sum of
`admission_started_boottime_ns` and `600_000_000_000`. Read failure, wrong
clock, overflow, or owner/boot drift
releases the still-empty lease and fails before any authority, key, endpoint,
admission, or root can exist. Every later normal-path time sample must be no
earlier than the admission-start sample and strictly earlier than the derived
deadline; equality is expired.

Under that lease, the controller performs this exact admission order:

1. validate origin PID/Thread/fork epoch, deployment executable/import
   manifests, native owners, boot epoch, and root absence;
2. load and authenticate the one active transport-authority manifest and both
   role identities, connect to the exact endpoint, and complete the signed
   challenge handshake without sending an operation request;
3. freshly authenticate the installed reviewed-Git stop authority and exact
   signed stop operation;
4. freshly capture and authenticate current daemon, persistent topology,
   topology lease, exact container/image/mount/hardening projections, exact
   container and network IDs, and both named-volume identities;
5. freshly authenticate the current trusted head and require it as the exact
   admitted predecessor for `clean_stop`;
6. consume the new ADR-0112 lifecycle-v2 historical-receipt handoff;
7. revalidate the lock, root absence, authority, operation, transport channel,
   topology/lease, trusted head, endpoint, deadlines, PID/Thread, and fork epoch
   against the captured immutable primitives; and
8. construct one unforgeable, process/thread/channel-bound admission and
   immediately consume it in the lifecycle repository to create/revalidate the
   root and retain/revalidate ordinal-one request intent.

The admission is never serialized and reserves nothing itself. Its exact
immutable primitive projection and digest bind both admission-start values; the
lifecycle root stores that projection digest and repeats both values. Caller-selected digests,
previously loaded objects, booleans, or equality of public views are not inputs.

The global launcher lease is the only cross-process host orchestration lock.
The v2 repository does not acquire a second flock. Supervisor registry mutexes
are process-local, bounded, and never acquired while the supervisor waits for
or attempts the host flock; the supervisor never acquires that flock at all.
Host order is global lease, native owner, repository operation, then process-
local registry mutex. No code may acquire those in reverse. Socket I/O and
external CALLs occur with no process-local mutex held. Lock loss or owner
substitution before possible root creation aborts; afterward it is
recovery-required.

### Freeze the lifecycle-v2 state machine

Normal success has this exact gap-free stage order:

The complete outcome lineage is gap-free across ordinals `0..23`: ordinal zero
is the root, ordinals `1..22` are progress records, and ordinal 23 is the sole
terminal outcome/fixed commit. Ordinal 19 is only the post-teardown
reauthentication intent; no `0..19` or other shortened success lineage exists.

| Ordinal | Stage | Required boundary |
|---:|---|---|
| 0 | `root_reserved` | One admission consumed; fixed permanent root durable |
| 1 | `clean_stop_request_intent_retained` | Exact request-basis digest, admission start/deadline, and intent evidence durable; derive the dispatch prefix from the stable ordinal-zero root plus this ordinal-one intent, then construct and dispatch the final signed request; no final-request byte feeds the intent |
| 2 | `clean_stop_result_retained` | Complete canonical signed result-envelope file, publication receipt, and exact typed evidence durable |
| 3 | `transport_cleanup_commitment_retained` | Signed supervisor cleanup commitment and exact host cleanup plan, owner, socket, key-path, challenge, nonce, and cleanup-deadline identities durable |
| 4 | `transport_channel_quiesced` | Host signer/challenge/nonce zeroized, both raw-key paths absent, accepted channel/listener closed, and exact socket inode unlinked before any effect |
| 5 | `pre_effect_reauthentication_intent_retained` | Exact ADR-0109 inputs durable before observation |
| 6 | `pre_effect_reauthentication_bound` | Fresh observation consumed through the v2 pre-effect seam and durable |
| 7 | `supervisor_container_stop_intent_retained` | Exact container ID and stop arguments durable |
| 8 | `supervisor_container_stop_result_retained` | Authenticated Docker result and exact-ID post-inspect durable |
| 9 | `source_container_stop_intent_retained` | Exact source container ID and stop arguments durable |
| 10 | `source_container_stop_result_retained` | Authenticated Docker result and exact-ID post-inspect durable |
| 11 | `supervisor_container_remove_intent_retained` | Exact admitted supervisor ID durable |
| 12 | `supervisor_container_remove_result_retained` | Exact-ID absence under unchanged daemon durable |
| 13 | `source_container_remove_intent_retained` | Exact admitted source ID durable |
| 14 | `source_container_remove_result_retained` | Exact-ID absence under unchanged daemon durable |
| 15 | `project_network_remove_intent_retained` | Exact admitted network ID durable |
| 16 | `project_network_remove_result_retained` | Exact-ID absence under unchanged daemon durable |
| 17 | `named_volume_preservation_intent_retained` | Both admitted volume identities and proof query durable |
| 18 | `named_volumes_preserved` | Both exact identity projections unchanged and delete-call count zero |
| 19 | `post_teardown_reauthentication_intent_retained` | Exact expected clean-stop head and prior bindings durable |
| 20 | `post_teardown_terminal_reauthentication_bound` | Distinct fresh observation and v2 terminal binding durable |
| 21 | `terminal_cleanup_intent_retained` | Exact empty normal-path tmpfs mounts, stopped/removed supervisor, absent socket/key paths, and remaining native-owner cleanup plan durable |
| 22 | `terminal_cleanup_confirmed` | Supervisor address space gone, every transport private/challenge/nonce buffer unreachable or zeroized, normal-path tmpfs mounts unmounted, and every success-relevant cleanup receipt durable |
| 23 | `confirmed_success` | Final prefix transcript, exact confirmed outcome, and fixed commit durable after cleanup |

At ordinal two, a valid signed error uses stage `clean_stop_error_retained`
instead, with its complete signed error-envelope file, publication receipt, and
typed evidence durable; it may be followed only by cleanup attempts and a
recovery-required terminal and never permits ordinal five or an effect. At any later ordinal, a
failed or ambiguous boundary may be followed only by best-effort exact owner
cleanup and the exact next-ordinal recovery-required outcome. A cleanup failure
through ordinal four is reason `transport_cleanup_unconfirmed`; a failure at
ordinal twenty-one/twenty-two is `terminal_cleanup_unconfirmed`. Neither can be
normalized into success or authorize continuation. If outcome publication is ambiguous, no
second outcome may be created until the fixed candidate and commit namespace
are reauthenticated.

Each intent is durable before its one exact CALL. Each authenticated result is
durable before the next intent. A CALL is never automatically repeated. A
missing result says nothing about call occurrence. Cleanup may close owned
descriptors and zeroize secrets; it may not remove or rewrite a possible root,
record, outcome, staging artifact, or commit.

The signed clean-stop result or error carries the complete nested supervisor
cleanup commitment and digest defined above. The supervisor quiescence action
was already directed by the durable request intent, so it does not depend on an
impossible post-result acknowledgement. Ordinal three on the normal-result path
repeats that digest and durably commits the host cleanup plan in typed
evidence with exactly `clean_stop_result_sha256`,
`supervisor_cleanup_commitment_sha256`, `channel_id`,
`host_process_epoch_sha256`, `host_socket_identity_sha256`,
`host_peer_credential_sha256`, `host_raw_key_path`, `host_raw_key_device`,
`host_raw_key_inode`, `host_challenge_sha256`,
`host_process_nonce_sha256`, and `cleanup_deadline_boottime_ns`. The path,
device/inode, challenge/nonce, channel, process, and deadline values must equal
the stable-loaded host custody and handshake inputs; none is caller supplied.
Here `clean_stop_result_sha256` is exactly the ordinary full signed-envelope
file digest retained at ordinal two, not the payload, terminal-projection, or
progress-record digest.
After the terminal-frame send attempt,
the admitted native supervisor owner stops accepting, closes the listener and
accepted descriptor, exact-inode-unlinks the socket, requires the already-
unlinked credential path to remain absent, and explicitly zeroizes its signer,
challenge, and process nonce; it exposes no new transport frame. The host
authenticates this sequence from the signed commitment, unchanged connected
peer through EOF, exact path/inode disappearance, and the admitted native
cleanup owner, then performs its
own close/unlink/zeroization.

That native quiescence sequence is a non-optional `finally` path after the one
terminal-frame send attempt and also runs in the owning process on handshake/
request rejection, disconnect, deadline, asynchronous failure, and owner
invalidation. It never waits for a host acknowledgement. A fork child instead
gets kernel-zeroed copied signer pages through `MADV_WIPEONFORK`, closes its
copied descriptors in the async-signal-safe native child handler, and never
unlinks a parent-owned pathname; the invalidated parent/native owner remains
responsible for exact pathname cleanup. The host likewise closes descriptors,
exact-inode-unlinks only its owned stale pathname when
identity permits, and zeroizes its signer/challenge/process nonce on every
terminal or failure path. Failure to complete or authenticate either cleanup is
recovery-required; neither endpoint may reopen a channel or continue to an
effect.

The supervisor-quiescence observation contract is exactly
`phase6d-trusted-time-graceful-stop-supervisor-transport-quiescence-observation-v2`,
status `supervisor_transport_quiescence_observed`; its fields are exactly
`contract_version`, `service`, `status`, `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, `channel_id`,
`supervisor_process_epoch_sha256`, `supervisor_cleanup_commitment_sha256`,
`supervisor_peer_credential_sha256`, `listener_path`, `listener_path_device`,
`listener_path_inode`, `listener_fd_socket_inode`, `accepted_fd_socket_inode`,
`supervisor_fd_table_sha256`, `channel_eof_observed`, `listener_fd_absent`,
`accepted_fd_absent`, `socket_path_absent`, `credential_path_absent`, and
`observed_boottime_ns`. The two FD/path-absence facts are the stable `/proc` and
directory observations defined above, not signer assertions. The host native-
cleanup receipt contract is exactly
`phase6d-trusted-time-graceful-stop-host-transport-cleanup-receipt-v2`, status
`host_transport_cleanup_completed`; its fields are exactly
`contract_version`, `service`, `status`, `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, `channel_id`,
`host_process_epoch_sha256`, `host_socket_identity_sha256`,
`host_peer_credential_sha256`, `host_raw_key_path`, `host_raw_key_device`,
`host_raw_key_inode`, `accepted_channel_closed`, `host_signer_zeroized`,
`host_challenge_zeroized`, `host_process_nonce_zeroized`,
`credential_path_absent`, `cleanup_started_boottime_ns`, and
`cleanup_completed_boottime_ns`. Both use service
`trusted-time-graceful-stop-lifecycle-v2`; their digests use the respective
ASCII domains
`AutoQuantTrader/trusted-time/graceful-stop/supervisor-transport-quiescence-observation/v2`
and
`AutoQuantTrader/trusted-time/graceful-stop/host-transport-cleanup-receipt/v2`,
one NUL byte, and the complete canonical object.

Ordinal four's typed evidence has exactly
`cleanup_commitment_record_sha256`, `supervisor_cleanup_commitment_sha256`,
`host_native_cleanup_receipt_sha256`, `supervisor_quiescence_observation_sha256`,
`channel_eof_observed`, `listener_fd_absent`, `accepted_fd_absent`,
`socket_path_absent`, `host_signer_zeroized`,
`host_challenge_zeroized`, `host_process_nonce_zeroized`,
`credential_paths_absent`, `cleanup_started_boottime_ns`, and
`cleanup_completed_boottime_ns`. Every boolean must be true. This result does
not infer supervisor memory erasure merely from a pre-erasure signature.

Ordinal twenty-one commits the remaining exact cleanup plan in evidence with
exactly `transport_quiescence_record_sha256`,
`supervisor_remove_result_sha256`, `transport_mount_identity_sha256`,
`host_secret_mount_identity_sha256`, `supervisor_secret_mount_identity_sha256`,
`recovery_secret_mount_absence_sha256`, `socket_path_absence_sha256`,
`credential_path_absence_sha256`, `native_owner_set_sha256`, and
`cleanup_deadline_boottime_ns`. Every identity comes from the stable current
mount/owner registries, the deadline is no later than the operation deadline,
and the supervisor-removal result must already be the exact ordinal-twelve
predecessor-chain artifact.

The empty-mount projection has exactly `environment`,
`graceful_stop_operation_id`, `lifecycle_root_sha256`, and the path-sorted
three-element `mounts`; each mount has exactly `path`, `mount_id`,
`mount_parent_id`, `mount_major_minor`, `mount_root`, `mount_options`,
`directory_device`, `directory_inode`, `directory_uid`, `directory_gid`,
`directory_mode`, and `entry_count`, which must be zero. Its digest domain is
`AutoQuantTrader/trusted-time/graceful-stop/empty-secret-mount-projection/v2`.
The unmount receipt has the same root correlators plus exact ordered mount IDs
for supervisor secrets, host secrets, then transport, and for each exactly
`unmounted`, `mount_absent`, and `completed_boottime_ns`; both booleans are true.
Its domain is
`AutoQuantTrader/trusted-time/graceful-stop/secret-mount-unmount-receipt/v2`.
The native-owner cleanup receipt has exactly the root/channel/process
correlators, `native_owner_set_sha256`, `owner_count_before`,
`owner_count_after`, `every_owner_invalidated`,
`every_private_buffer_zeroized_or_process_destroyed`, and
`completed_boottime_ns`; after-count is zero and both booleans are true. Its
domain is `AutoQuantTrader/trusted-time/graceful-stop/native-owner-cleanup-receipt/v2`.
Every digest uses its ASCII domain, one NUL byte, and its complete canonical
object.

`native_owner_set_sha256` covers a kind-sorted list whose entries have exactly
`owner_kind`, `owner_process_epoch_sha256`, and `owner_nonce_sha256`; the closed
kind set is endpoint signer, transport channel, Docker effect client,
pre-effect issuer, or post-teardown issuer. It deliberately excludes the
nonsecret, non-effecting lifecycle/outcome repository owner and global lease
descriptor that must survive solely to publish ordinal twenty-three and then
be invalidated/released. Those exclusions cannot hold a socket, credential,
Docker method, provider observation capability, or private buffer. Adding any
other exclusion or owner kind rejects.

Ordinal twenty-two
requires the exact supervisor container-removal result (therefore kernel
destruction of its address space), continued absence of listener/socket/key
paths, empty transport/host-secret/supervisor-secret tmpfs roots, absence of a
normal-path recovery-secret mount, successful unmount of the three empty normal
tmpfs mounts, and invalidation of every remaining signer/channel/effect/
reauthentication owner. Its evidence has exactly `cleanup_intent_sha256`,
`transport_quiescence_record_sha256`, `supervisor_remove_result_sha256`,
`socket_absence_sha256`, `credential_path_absence_sha256`,
`empty_mount_projection_sha256`, `unmount_receipt_sha256`,
`native_owner_cleanup_receipt_sha256`, `all_private_material_unreachable`, and
`cleanup_completed_boottime_ns`; the boolean must be true. The final transcript
ends at this record. Only then may ordinal twenty-three publish confirmed
success. After its fixed commit, only already-empty process-local registry
invalidation and lease-descriptor close remain. Neither owns a secret, socket,
effect, observation capability, or durable candidate; neither is an ordinal,
cleanup prerequisite, or deadline check. Failure is operational telemetry only
and cannot invalidate/reclassify the fixed commit. The controller exits after
the bounded close attempt, and kernel process exit guarantees descriptor/flock
release even if user-space disposal reports failure.

### Make every live registry fork-safe before locking

Both fixed launchers must load an admitted native fork guard before Python
initialization. Every live endpoint, key owner, channel, admission, lifecycle,
effect, reauthentication, and outcome registry binds origin PID, exact
`threading.Thread`, interpreter identity, and a native fork epoch. Every
entrypoint, weak-reference callback, and cleanup path checks PID and fork epoch
before acquiring a Python or native registry lock or dereferencing an inherited
owner.

The native guard registers `pthread_atfork`. Its child handler performs only
async-signal-safe operations: atomically increments the fork epoch, marks the
process invalid, and closes every descriptor in a fixed native owner table.
It acquires no inherited mutex and calls no Python. A later Python child hook,
after native invalidation, replaces Python locks and empties registries without
touching inherited owners. The child gains no channel, cleanup, recovery,
outcome, or effect authority. The parent keeps its original epoch only if the
parent handler confirms the owner table unchanged; otherwise the operation
fails closed.

No process creation is permitted while a live v2 owner, registry, admission,
root transaction, or effect authority exists. The implementation must not use
Docker CLI, Compose, `subprocess`, `fork`, `vfork`, `clone`, `posix_spawn`, or
`exec` for v2 effects. A fixed seccomp profile denies process-creation syscalls
after activation. The at-fork protocol remains mandatory defense and test
surface rather than permission to fork.

### Use an exact method-narrowed Docker Engine API effect boundary

V2 effects use a dedicated bounded HTTP/1.1 client over the admitted exact
root-owned `unix:///var/run/docker.sock` and fixed Docker Engine API `/v1.45`.
The client has no generic request method. Its only mutation methods are exact-ID
container stop, exact-ID container delete, and exact-ID network delete. Its
read methods are exact-ID container/network/volume inspect and daemon identity.
It has no image, exec, create, start, restart, kill, prune, Compose, broad
project, or volume-delete method. Redirects, connection replacement, chunked or
unbounded bodies, upgrade, streaming, unknown status, and body/schema excess
reject.

The client emits only the following literal HTTP request targets. `{id}` is an
already-admitted 64-character lowercase hexadecimal full ID, and `{name}` is
one of the two literal volume names below; path escaping, abbreviations,
names-as-container-targets, extra slashes, percent encoding, fragments, and
alternate query ordering reject.

| Purpose | Method and exact request target | Normal status | Request body |
|---|---|---:|---|
| daemon identity | `GET /v1.45/info` | 200 | absent |
| present container inspect | `GET /v1.45/containers/{id}/json` | 200 | absent |
| removed container post-inspect | `GET /v1.45/containers/{id}/json` | 404 | absent |
| present network inspect | `GET /v1.45/networks/{id}` | 200 | absent |
| removed network post-inspect | `GET /v1.45/networks/{id}` | 404 | absent |
| volume inspect | `GET /v1.45/volumes/{name}` | 200 | absent |
| graceful container stop | `POST /v1.45/containers/{id}/stop?t=30` | 204 | absent |
| preserving container delete | `DELETE /v1.45/containers/{id}?v=false&force=false&link=false` | 204 | absent |
| network delete | `DELETE /v1.45/networks/{id}` | 204 | absent |

The stop query is exactly the single pair `t=30`. A `signal` query is forbidden:
the Engine uses the admitted image configuration's exact `Config.StopSignal`,
with null meaning its documented default `SIGTERM`; that projection is bound at
admission and revalidated before the call. The container-delete query is
literally `v=false&force=false&link=false`: anonymous volumes are preserved,
the container is not force-removed, and legacy link removal is disabled. The
network delete and every GET have an empty query. No endpoint accepts an
application body, including zero-byte JSON; `absent` means no body bytes.
The canonical `ordered_query` values are exactly `[["t","30"]]` for stop,
`[["v","false"],["force","false"],["link","false"]]` for container
delete, and `[]` for every GET and network delete.

Every request writes one fixed HTTP/1.1 header profile in this order:
`Host: docker`, `Accept: application/json`, and `Connection: close`; POST and
DELETE then add `Content-Length: 0`. GET must not carry `Content-Length`.
`User-Agent`, `Content-Type`, `Transfer-Encoding`, `Expect`, authorization,
caller-supplied, duplicate, differently cased, or any other request header
rejects before socket I/O. The dedicated parser separately enforces the exact
bounded response status/body schema; response metadata is never reflected into
a later request.

Responses are HTTP/1.1 only. The status/header block is at most 16,384 bytes,
contains at most 64 CRLF-terminated lines, and has no obs-fold, bare LF, NUL,
control character other than horizontal tab in a value, or line longer than
1,024 bytes. A reason phrase is ignored only after validating at most 64 visible
ASCII bytes. `Transfer-Encoding`, `Upgrade`, `Content-Encoding`, `Trailer`, 1xx,
duplicate header names after ASCII-lowercase normalization, and a
present `Connection` value other than case-insensitive `close` reject. A JSON
response requires exactly one canonical decimal `Content-Length` with no
leading zero and exactly one `Content-Type: application/json`; the client reads
exactly that many bytes and then requires EOF. A 204 response permits
`Content-Length` to be absent or exactly `0`, permits `Content-Type` to be absent
or exactly `application/json`, and requires zero body bytes before EOF. All
other syntactically valid bounded response headers are explicitly ignored by
the typed decoder, not treated as schema fields. `response_framing_sha256` is
SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/docker-response-framing/v2`, one NUL
byte, and the exact received status line plus every header line and the terminal
empty CRLF, preserving original bytes and order. This is the only ignored-header
rule; framing headers never use it.

Raw body ceilings are endpoint-specific and checked against `Content-Length`
before allocation: 1,048,576 bytes for `/info`, 524,288 for container inspect,
262,144 for network inspect, 131,072 for volume inspect, 4,096 for an accepted
404 error, and zero for a 204. Premature EOF, surplus bytes, close before the
declared length, length above the ceiling, chunking, compression, or truncation
is ambiguous. `response_body_sha256` is ordinary SHA-256 of the exact received
body bytes, including an accepted optional final LF on a 404, before typed
projection.

JSON is decoded with duplicate-key detection at every depth, UTF-8 strictness,
maximum depth 16, at most 16,384 nodes, strings at most 65,536 UTF-8 bytes, and
signed 64-bit integers only; floats, non-finite values, and invalid surrogate
forms reject. Docker's large response objects are not claimed as a closed whole
schema. Instead, the decoder reads these exact allowlisted projections:

- `/info`: `daemon_id`, `docker_root_dir`, `name`, `server_version`,
  `operating_system`, `os_type`, `architecture`, `storage_driver`, and sorted-
  unique `security_options`, mapped respectively from `ID`, `DockerRootDir`,
  `Name`, `ServerVersion`, `OperatingSystem`, `OSType`, `Architecture`, `Driver`,
  and `SecurityOptions`;
- container inspect: `container_id`, `image_id`, `name`, and exact nested
  `state`, `config`, `host_config`, `mounts`, and `networks`. `state` has exactly
  `status`, `running`, `paused`, `restarting`, `oom_killed`, `dead`, `pid`,
  `exit_code`, `started_at`, and `finished_at`; `config` has `image`,
  `stop_signal`, `user`, and `labels_sha256`; `host_config` has `network_mode`,
  `readonly_rootfs`, `privileged`, sorted `cap_add`, sorted `cap_drop`, sorted
  `security_opt`, `pids_limit`, `nano_cpus`, and `memory`; every sorted `mounts`
  entry has exactly `type`, `name`, `source`, `destination`, `driver`, `mode`,
  `rw`, and `propagation`; and every name-sorted `networks` entry has exactly
  `name`, `network_id`, `endpoint_id`, `gateway`, `ip_address`,
  `global_ipv6_address`, and `mac_address`;
- network inspect: `network_id`, `name`, `created`, `scope`, `driver`,
  `enable_ipv6`, `internal`, `attachable`, `ingress`, `ipam_sha256`,
  `options_sha256`, `labels_sha256`, and sorted-unique `container_ids`; and
- volume inspect: `name`, `driver`, `mountpoint`, `created_at`, `status_sha256`,
  `labels_sha256`, `scope`, `options_sha256`, `host_mount_device`, and
  `host_mount_inode`. The last two are stable host `stat` facts collected after
  the decoded mountpoint is rebound beneath Docker's admitted root.

Every named raw path is required and must have its exact string/integer/boolean/
null/list/map type except this closed optional set: raw `Config.StopSignal`
missing, null, or empty string projects to `config.stop_signal=null` (the
reviewed Docker default `SIGTERM`); missing or null `HostConfig.CapAdd`,
`CapDrop`, or `SecurityOpt` projects to the respective null list; missing or
null `HostConfig.PidsLimit` projects to null; and missing or null volume
`CreatedAt`, `Options`, or `Status` projects to null. No other missing/null
normalization exists. Label, option, auxiliary-address, and
volume-status projections are lexicographically sorted key/value pairs; values
are strings, except an explicitly nullable Docker map is represented by JSON
null rather than an empty map. `ipam_sha256` hashes an exact object with
`driver`, lexicographically sorted string-valued `options` or null, and raw-order
`config`; each config entry has exactly `subnet`, `ip_range`, `gateway`, and
lexicographically sorted string-valued `auxiliary_addresses` or null; each of
those four config values may be null, while the driver and config list are
required.
Its domain is
`AutoQuantTrader/trusted-time/graceful-stop/docker-network-ipam-projection/v2`,
one NUL byte, and the complete canonical IPAM projection. The other map digests
use their enclosing projection domain plus a literal `/labels`, `/options`, or
`/status` suffix, one NUL byte, and the complete canonical pair list. Unknown raw Docker
JSON fields at any depth are deliberately ignored after the bounded duplicate-
aware parse, but remain committed by `response_body_sha256`; an unknown field
cannot replace, change the type of, or supply a required projected field. The
canonical projection digest uses the complete respective ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/docker-info-projection/v2`,
`AutoQuantTrader/trusted-time/graceful-stop/docker-container-projection/v2`,
`AutoQuantTrader/trusted-time/graceful-stop/docker-network-projection/v2`, or
`AutoQuantTrader/trusted-time/graceful-stop/docker-volume-projection/v2`, one
NUL byte, and the exact projection; it is retained as
`response_projection_sha256`.

Normal 204 mutation responses have the fixed zero-body digest and a projection
of exactly `{"disposition":"accepted","http_status":204}` under the domain
`AutoQuantTrader/trusted-time/graceful-stop/docker-mutation-projection/v2`. A
removed-container post-inspect accepts only status 404 and a raw object with the
single field `message` exactly `No such container: {id}`; a removed-network
post-inspect accepts only the single-field message `network {id} not found`.
The raw body may be exactly the compact JSON object or that object plus one LF.
Any other key, message, whitespace, or body rejects. The typed 404 projection
has exactly `entity_kind`, `entity_id`, `http_status`, and `message`, with kind
`container` or `network`, status integer 404, and the exact admitted full ID and
message; its domain is
`AutoQuantTrader/trusted-time/graceful-stop/docker-not-found-projection/v2`.
Every projection digest uses its stated ASCII domain, one NUL byte, and the
complete canonical projection. A stopped-container 200 projection must
retain the same container/image identity with `state.running=false`,
`state.paused=false`, `state.restarting=false`, `state.dead=false`,
`state.status=exited`, and the admitted stop-signal configuration. A missing
volume, an unexpected 404/304, or identity/projection drift is never normal
success.

Every HTTP exchange uses one fresh nonblocking `AF_UNIX/SOCK_STREAM`
connection with `Connection: close`; a connection is never pooled, retried, or
reused for another request. Before connect the controller reserves the ordinal
and validates only the pathname/mount facts. Immediately after `connect(2)`
completes and before the first request byte, it captures the immutable identity
core; after the final response revalidation it seals the exact canonical
`connection_identity` object with these fields only:

- `contract_version="phase6d-trusted-time-graceful-stop-docker-connection-identity-v2"`,
  `service="trusted-time-graceful-stop-docker-v2"`,
  `status="docker_connection_bound"`, `environment`,
  `graceful_stop_operation_id`, `channel_id`, and `api_version="v1.45"`;
- `connection_ordinal`, a gap-free integer in `0..17` assigned before connect
  and never reassigned, even after an error;
- `docker_socket_path="/var/run/docker.sock"`, `socket_mount_id`, `socket_mount_parent_id`,
  `socket_mount_major_minor`, `socket_mount_root`, `socket_mount_point`,
  `socket_mount_filesystem_type`, `socket_mount_source`,
  `socket_mount_options`, `socket_mount_super_options`,
  `socket_path_device`, `socket_path_inode`, `socket_path_uid`,
  `socket_path_gid`, and `socket_path_mode` from the admitted host path and its
  `/proc/self/mountinfo` entry;
- `peer_uid`, `peer_gid`, `peer_pid`, `daemon_start_time_ticks`,
  `daemon_proc_device`, `daemon_proc_inode`,
  `daemon_pid_namespace_inode`, `daemon_executable_device`,
  `daemon_executable_inode`, `daemon_executable_size`,
  `daemon_executable_uid`, `daemon_executable_gid`,
  `daemon_executable_mode`, `daemon_executable_nlink`,
  `daemon_executable_sha256`, and `daemon_cgroup_sha256`, where the peer values are one `SO_PEERCRED` sample,
  UID/GID are exactly `0/0`, PID/start time/executable identify the same live
  daemon, and the namespace inode is from `/proc/<peer_pid>/ns/pid`;
- `local_socket_device`, `local_socket_inode`, and `local_socket_cookie`, from
  `fstat(2)` and the positive 64-bit Linux `SO_COOKIE`; these, rather than the
  process-local numeric file descriptor, are the non-reusable local connection
  identity;
- `admitted_daemon_info_projection_sha256`, which is JSON null for ordinal zero
  and the exact ordinal-zero `/info` projection digest for ordinals `1..17`;
  and
- `path_preconnect_validated_boottime_ns`, `opened_boottime_ns`,
  `pre_request_revalidated_boottime_ns`,
  `response_headers_revalidated_boottime_ns`,
  `response_complete_revalidated_boottime_ns`, and
  `call_deadline_boottime_ns`.

All strings, hashes, and integers use the global canonical rules; mount options
and super-options are the exact sorted-unique option strings, modes are unsigned
permission/type integers, all inode/device/PID/start/cookie values are positive,
and timestamps are nonnegative signed 64-bit integers in the listed
nondecreasing order, with
`response_complete_revalidated_boottime_ns < call_deadline_boottime_ns`. The identity digest is
SHA-256 over the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/docker-connection-identity/v2`, one
NUL byte, and the complete canonical object. The pre-connect checkpoint only
re-stats the literal socket path/mount. After connect, immediately before the
request, after response headers, and after the complete body/EOF but before
close, the controller re-stats that path/mount and re-reads peer credential,
daemon `/proc` identity, `fstat`, and `SO_COOKIE`; every post-connect sample
must equal the captured core. The trace's call-start time equals
`path_preconnect_validated_boottime_ns`, and its call-completion time equals
`response_complete_revalidated_boottime_ns`. The call's result retains the
sealed identity object and digest. A pathname swap, remount, peer/process
restart, local socket replacement, closed-before-validation descriptor, missing
`SO_COOKIE`, or inability to prove equality is ambiguous and
recovery-required.

The daemon process fields have one exact preimage and reader. The controller
opens `/proc/<peer_pid>` as a no-follow directory and binds its device/inode.
At each post-connect checkpoint it reads `/proc/<peer_pid>/stat` completely to
EOF with a 16,384-byte ceiling, requires the documented `proc_pid_stat(5)` PID
prefix and parenthesized `comm`, tokenizes the suffix after its final `") "`
delimiter, and parses unsigned decimal field 22 as
`daemon_start_time_ticks`; missing, extra-sign, overflow, truncation, or a
different value rejects. It opens that proc directory's `exe` entry read-only,
following only the kernel procfs executable link to the referenced file inode,
and requires a root-owned regular file, positive link count, size at most
268,435,456 bytes, and no group/world write bit. The executable device, inode,
size, UID/GID, permission/type mode, and link count are its `fstat` values;
`daemon_executable_sha256` is ordinary SHA-256 of exactly `size` file bytes,
with equal pre/post `fstat` and EOF at exactly that boundary. It reads
`/proc/<peer_pid>/cgroup` completely to EOF twice with a 65,536-byte ceiling,
requires one nonempty byte-identical result ending in LF, and hashes those exact
raw bytes as `daemon_cgroup_sha256`. The proc directory, PID namespace inode,
stat start time, executable facts/bytes, and cgroup bytes must equal their
captured values at every checkpoint; PID reuse, executable replacement, short/
growing reads, or any unstable proc value is ambiguous.

For every request the client constructs `docker_request_semantic_sha256` as
SHA-256 over the ASCII domain `autoquant.trusted-time.docker-request.v2`, one
NUL byte, and the canonical request object.
That canonical object has exactly `api_version`, `method`, `path`,
`ordered_query`, `request_headers`, `body_presence`, `body_length`, and
`body_sha256`. `ordered_query` is the literal ordered pair list represented in
the table, `request_headers` is the literal ordered header list above,
`body_presence` is `absent`, `body_length` is integer zero, and `body_sha256` is
the literal SHA-256-of-zero-bytes value
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Thus an omitted or reordered flag, `v=true`, an added query/header, a different
signal, or any body byte changes the digest and rejects. The exact digest is
retained before the CALL, repeated in its result,
and included in the append-only method-trace entry. That entry's canonical
object has exactly `trace_ordinal`, `request_semantic_sha256`, `http_status`,
`response_framing_sha256`, `response_body_sha256`,
`response_projection_sha256`, `connection_identity_sha256`,
`call_started_boottime_ns`, `call_completed_boottime_ns`, and
`previous_trace_entry_sha256`; its digest is SHA-256 over the ASCII domain
`autoquant.trusted-time.docker-trace-entry.v2`, one NUL byte, and that object.
`trace_ordinal` equals the connection ordinal; ordinal zero has
`previous_trace_entry_sha256=null`, and every ordinal `1..17` names exactly the
immediately preceding entry digest. All response and connection digests equal
the artifacts produced by that same exchange.
Post-inspect and volume-proof GET digests are retained the same way. Normal
mutation success accepts only the status in the table plus the independent
post-inspect semantic; 304, an unexpected 404, and every other response are
failure or ambiguity, never an idempotent-success shortcut.
`docker_api_trace_sha256` is the terminal digest of that gap-free ordered chain.
A trace entry without the matching durable intent/result or a durable result
without its matching trace entry is recovery-required.

The controller also constructs one exact `docker_http_exchange` object per
request. It has only `exchange_kind`, `target_kind`, `target_identity`,
`request_semantic_sha256`, `connection_identity_sha256`, `http_status`,
`response_framing_sha256`, `response_body_sha256`,
`response_projection_sha256`, `trace_entry_sha256`,
`call_started_boottime_ns`, and `call_completed_boottime_ns`.
`exchange_kind` is exactly one of `admission_read`, `mutation`,
`post_inspect`, or `volume_proof`; target kind is exactly `daemon`,
`container`, `network`, or `volume`; target identity is `docker-daemon`, the
admitted full container/network ID, or the literal admitted volume name.
Request, framing, raw body, typed projection, trace, and connection digests are
the exact artifacts defined above, and the exchange timestamps equal the trace
timestamps. Its digest is SHA-256 over
`AutoQuantTrader/trusted-time/graceful-stop/docker-http-exchange/v2`, one NUL
byte, and the complete canonical object.

The same-lock admission performs these six reads literally and only in this
order, one request per fixed connection ordinal: `0: GET /v1.45/info`;
`1: GET /v1.45/containers/{supervisor_full_id}/json`; `2: GET
/v1.45/containers/{source_full_id}/json`; `3: GET
/v1.45/networks/{project_network_full_id}`; `4: GET
/v1.45/volumes/autoquanttrader-trusted-time_chrony_command_socket`; and `5: GET
/v1.45/volumes/autoquanttrader-trusted-time_chrony_state`. The full IDs and
literal volume names come from the preceding bounded local Compose/config
admission; no Docker list/name discovery is permitted.

Those six exchanges produce one canonical admission object with exactly
`contract_version="phase6d-trusted-time-graceful-stop-docker-admission-capture-v2"`,
`service="trusted-time-graceful-stop-docker-v2"`,
`status="docker_admission_captured"`, `environment`,
`graceful_stop_operation_id`, `channel_id`, `first_connection_ordinal=0`,
`last_connection_ordinal=5`, `ordered_request_semantic_sha256_list`,
`ordered_connection_identity_list`,
`ordered_connection_identity_sha256_list`,
`ordered_http_exchange_list`, `ordered_http_exchange_sha256_list`,
`ordered_trace_entry_list`, `ordered_trace_entry_sha256_list`,
`daemon_info_projection_sha256`,
`supervisor_container_projection_sha256`,
`source_container_projection_sha256`, `project_network_projection_sha256`,
`command_socket_volume_projection_sha256`,
`state_volume_projection_sha256`, `capture_started_boottime_ns`, and
`capture_completed_boottime_ns`. Each of the seven ordered lists has exactly six
elements in the literal order above. Every connection or trace object and every
exchange is the complete exact object defined above and re-encodes to its same-
index digest; every request digest equals the same-index exchange request,
every connection digest equals that exchange's connection correlator, and every
trace object/digest equals that exchange's trace correlator. For each index the
trace's request/connection/status/framing/body/projection/start/completion fields
equal the corresponding exchange fields, the connection start/completion fields
equal those timestamps, and exchange kind/target plus the digest-resolved
request equal the literal read at that index. Target kind/identity are exactly
`daemon`/`docker-daemon`, supervisor `container`/full ID, source
`container`/full ID, `network`/project full ID, `volume`/command-socket name,
then `volume`/state name. Every named projection equals its corresponding exchange projection,
and the capture timestamps equal the first call start and last call completion.
`docker_admission_capture_sha256` is SHA-256 over
`AutoQuantTrader/trusted-time/graceful-stop/docker-admission-capture/v2`, one
NUL byte, and that complete object. This digest and all seven ordered lists are
direct fields of the topology admission object hashed into `admission_sha256`
and therefore the v2 root. The six reads are not effect calls. During the
lifecycle, daemon continuity is revalidated locally from the admitted socket
inode/mount, peer credential, daemon process identity, and each exact
connection identity; it does not emit an implicit `/info` helper request. Any
additional or reordered GET is outside the admitted plan and
recovery-required.

Before and after every call, the client revalidates the Docker socket inode and
mount, `SO_PEERCRED`, admitted daemon identity, global lease, process/thread/
fork epoch, exact expected lifecycle prefix, and deadline. A result is accepted
only when the primary exchange stayed on its one unchanged connection, the
independent exact-ID post-inspect stayed on its distinct unchanged connection,
both connection identities name the same admitted daemon process, and both have
the exact expected HTTP status/projection. A lost connection or response is
ambiguous even when a later inspect shows the requested state.

Each container-stop, container-remove, or network-remove result semantic is one
canonical object with these fields only: `contract_version`, `service`,
`status`, `environment`, `graceful_stop_operation_id`, `root_sha256`,
`result_kind`, `target_kind`, `target_id`,
`docker_admission_capture_sha256`,
`admitted_daemon_info_projection_sha256`,
`primary_request_semantic_sha256`, `primary_connection_identity`,
`primary_connection_identity_sha256`, `primary_exchange`,
`primary_exchange_sha256`, `post_inspect_request_semantic_sha256`,
`post_inspect_connection_identity`,
`post_inspect_connection_identity_sha256`, `post_inspect_exchange`,
`post_inspect_exchange_sha256`,
`ordered_connection_identity_sha256_list`,
`ordered_trace_entry_list`, `ordered_trace_entry_sha256_list`,
`call_started_boottime_ns`,
`call_completed_boottime_ns`, and `outcome`. The nested identities and
exchanges and both ordered trace entries are their complete exact canonical
objects; every adjacent or same-index digest
must re-encode from its object, the request digests equal their exchange fields,
each trace object/digest equals its exchange trace correlator, and every trace
request/connection/status/framing/body/projection/timestamp field equals the
corresponding exchange field. The connection start/completion timestamps equal
their exchange timestamps; the two-element connection and trace lists preserve
primary-then-post-inspect order; the post-inspect trace predecessor is the
primary trace digest and the primary predecessor is the exact prior global
trace head; both targets and digest-resolved requests equal the fixed result
kind/target; and the outer timestamps equal primary call start and post-inspect
call completion. The outer target kind/ID equals the durable prior intent and
admitted full ID, both exchange target kind/identities, both digest-resolved
request paths, and the post-inspect typed projection identity. The primary 204
mutation projection deliberately carries no target field. The primary exchange
kind is exactly `mutation`; the second is exactly `post_inspect`.

The only allowed contract/status/kind/domain combinations for that shape are:

- `phase6d-trusted-time-graceful-stop-docker-container-stop-result-v2`,
  `container_stop_confirmed`, `container_stop`, target kind `container`, outcome
  `stopped`, and domain
  `AutoQuantTrader/trusted-time/graceful-stop/docker-container-stop-result/v2`;
- `phase6d-trusted-time-graceful-stop-docker-container-remove-result-v2`,
  `container_removal_confirmed`, `container_remove`, target kind `container`,
  outcome `absent`, and domain
  `AutoQuantTrader/trusted-time/graceful-stop/docker-container-remove-result/v2`;
  or
- `phase6d-trusted-time-graceful-stop-docker-network-remove-result-v2`,
  `network_removal_confirmed`, `network_remove`, target kind `network`, outcome
  `absent`, and domain
  `AutoQuantTrader/trusted-time/graceful-stop/docker-network-remove-result/v2`.

`service` is always `trusted-time-graceful-stop-docker-v2`; environment,
operation, root, admission, and daemon-info digests equal the fixed lifecycle
values. Stop requires a primary 204 mutation projection followed by the exact
200 stopped-container projection. Remove requires a primary 204 mutation
projection followed by the exact typed 404 projection. A result semantic digest
is SHA-256 over its listed ASCII domain, one NUL byte, and the complete canonical
object; that is the `result_semantic_sha256` stored by its lifecycle result.

The volume-preservation result semantic is a distinct canonical object with
exactly `contract_version="phase6d-trusted-time-graceful-stop-docker-volume-preservation-result-v2"`,
`service="trusted-time-graceful-stop-docker-v2"`,
`status="named_volumes_preserved"`, `environment`,
`graceful_stop_operation_id`, `root_sha256`,
`result_kind="volume_preservation"`,
`target_kind="named_volume_set"`, `target_names`,
`docker_admission_capture_sha256`,
`admitted_daemon_info_projection_sha256`,
`admission_volume_projection_sha256_list`,
`ordered_request_semantic_sha256_list`,
`ordered_connection_identity_list`,
`ordered_connection_identity_sha256_list`, `ordered_http_exchange_list`,
`ordered_http_exchange_sha256_list`, `ordered_trace_entry_list`,
`ordered_trace_entry_sha256_list`,
`post_volume_projection_sha256_list`, `volume_delete_call_count`,
`proof_started_boottime_ns`, `proof_completed_boottime_ns`, and
`outcome="volumes_preserved"`. `target_names` is exactly the command-socket
then state-volume literal list; every other ordered list has exactly two items
in that same order. Environment, operation, root, admission-capture, and
daemon-info digests equal the fixed lifecycle/root values. The admission
projection list is exactly the command-socket then state-volume projection
digests in the root-bound Docker admission capture; the post list is exactly
the same-index exchange response-projection digests; and those two lists are
byte-equal. `proof_started_boottime_ns` equals the first exchange start and
`proof_completed_boottime_ns` equals the second exchange completion. Each
exchange is a 200 `volume_proof`, and `volume_delete_call_count` is integer
zero. Complete connection, exchange, and trace objects re-encode to
their same-index digests, and request/connection/trace correlators equal those
in the same-index exchange. Every trace status/framing/body/projection/timestamp
field equals its exchange, each connection start/completion equals that
exchange, each target and digest-resolved request equals the fixed literal
volume GET, each exchange kind is `volume_proof`, its target kind is `volume`,
and its target identity equals same-index `target_names`. The second trace's predecessor is the first trace digest while
the first predecessor is the exact prior global trace head; connection and trace
ordinals are exactly 16 then 17. Its digest is SHA-256 over
`AutoQuantTrader/trusted-time/graceful-stop/docker-volume-preservation-result/v2`,
one NUL byte, and the complete object. No generic map, omitted object, digest-
only reconstruction, or extra result field is accepted.

After admission, connection ordinals and exchanges are fixed literally as
`6` supervisor stop, `7` supervisor post-inspect, `8` source stop, `9` source
post-inspect, `10` supervisor delete, `11` supervisor absent post-inspect, `12`
source delete, `13` source absent post-inspect, `14` project-network delete,
`15` network absent post-inspect, `16` command-socket-volume proof, and `17`
state-volume proof. The method trace is one gap-free chain over ordinals
`0..17`; no ordinal may be skipped, reused, or reordered.

The effect order is fixed:

1. stop the exact admitted supervisor container ID with a 30-second timeout;
2. stop the exact admitted source container ID with a 30-second timeout;
3. delete the exact supervisor container ID;
4. delete the exact source container ID; and
5. delete the exact project-network ID.

Each operation has its own prior durable intent and later durable authenticated
result. A name, label, Compose project, list index, replacement ID, or generic
stopped/absent observation cannot select a target. The source never stops first
or concurrently.

The volume proof queries exactly
`autoquanttrader-trusted-time_chrony_command_socket` and
`autoquanttrader-trusted-time_chrony_state`. For each, the canonical identity
projection binds name, driver, scope, mountpoint, options, labels, creation
identity, and stable host mount device/inode. It excludes mutable volume
contents. Both post-teardown projections must equal admission, and the retained
method trace must prove `volume_delete_call_count=0`. The client type and import
guard make `/volumes/...` DELETE, prune, `down --volumes`, and unbounded request
construction unreachable. The same proof rejects any container DELETE whose
exact request digest does not encode `v=false`, so anonymous-volume removal via
a container-delete flag is counted as forbidden volume-delete reachability even
without a `/volumes` endpoint call. Missing, replaced, or drifted volume
identity is recovery-required, never success.

### Use distinct pre-effect and post-teardown ADR-0109 bindings

After ordinal four and before any container or network effect, the controller
durably retains the pre-effect intent, creates a new one-shot ADR-0109 issuer,
performs its exact 120-second S1/provider/S2 observation, and consumes it through
a new private v2 pre-effect binding seam. That seam binds the exact operation,
root, request, result, channel, expected `CLEAN_STOP` record, topology, provider
identity, and observation primitives. Ordinal six retains those primitives and
binding digest, not a serialized process seal.

After ordinal eighteen, the controller durably retains a separate terminal-
reauthentication intent and creates a second ADR-0109 issuer. Its observation
must start strictly after the durable network-removal result and volume proof.
A different private v2 terminal seam binds it to the exact operation, root,
exact published prefix transcript through ordinal eighteen, expected clean-stop
head, pre-effect binding, teardown results, volume proof, and provider identity.
It must be a distinct exact object,
issuer identity, challenge, observation interval, and binding digest. Reuse or
adaptation of the pre-effect observation rejects.

The pre-effect binding authorizes only construction of the next lifecycle
intent while the complete controller context remains live; it is not terminal
evidence. The post-teardown binding is required for confirmed success but
authorizes no additional effect. Failure or ambiguous STORE at either boundary
is recovery-required.

### Resolve recovery as classification without continuation

Lifecycle v2 never continues an effecting prefix after process loss, host
restart, fork invalidation, lock loss, deadline expiry, or ambiguous return.
This remains true even when the last durable record is an authenticated result.
There is no automatic or manual v2 retry, replay, resume, skip, compensation,
or effect continuation.

A separately admitted recovery-classifier profile may perform only these
actions while holding the same global launcher lock:

1. stable-load and authenticate the fixed root, complete namespace, transcript,
   every transcript-referenced signed wire artifact, staging names, outcome
   candidate, and commit marker; recompute the checked admission-start plus
   600-second deadline and require equality everywhere it is repeated;
2. report an exact already committed confirmed-success or recovery-required
   outcome without mutation;
3. if there is one exact known gap-free v2 prefix and no outcome publication
   may have begun, publish/revalidate its deterministic classified-prefix
   transcript, consume a signed recovery-classification envelope from the root-
   pinned manifest's recovery key, durably append the exact next-ordinal
   `recovery_classification_intent_retained` record, publish the distinct final
   transcript ending at that intent, and publish only the deterministic
   following-ordinal recovery-required outcome; or
4. if one exact content-addressed outcome candidate exists and only its fixed
   commit is uncertain, revalidate and commit that same candidate—never create
   another outcome. A confirmed-success candidate is eligible only when an
   exact canonical fixed-marker staging or final preimage authenticates the
   candidate and contains the matching protocol start, five-second publication-
   authorization cutoff, admission start, checked 600-second operation cutoff,
   and final authorization sample strictly before both. An exact recovery-required candidate's own
   non-null sample may authorize finalization under its bound timing rules; a
   confirmed-success candidate alone does not prove that the final check
   occurred and permits no recovery write.

A prefix containing ordinal two is known only when its transcript, progress
evidence, nested publication receipt, digest-derived wire filename, complete
signed-envelope bytes, payload/schema/signature/channel/lifecycle-dispatch-
prefix/counter/deadline, recomputation from the exact root and ordinal-one
request intent, and result-versus-error choice all reauthenticate to one value. A missing/orphaned
wire file, progress-only digest, payload-only reconstruction, or result/error
conflict is retention-unconfirmed and permits no recovery write.

The recovery-classification contract is
`phase6d-trusted-time-graceful-stop-recovery-classification-envelope-v1`.
Its exact unsigned fields are `contract_version`, `service`, `status`,
`environment`, `graceful_stop_operation_id`, `root_sha256`,
`admission_started_boottime_ns`, `operation_deadline_boottime_ns`,
`transcript_sha256`, `last_ordinal`, `last_stage`, `reason_code`,
`transport_authority_manifest_sha256`, `key_generation`, `recovery_key_id`,
`operator_nonce_base64`, and `issued_at_utc`; encoded bytes add only
`signature_ed25519_base64`. Status is `recovery_classification_requested`.
The nonce is exactly 32 bytes from blocking `getrandom`. UTC is audit-only and
does not expire or authorize the envelope.

The signature input is the ASCII domain
`AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1`, one NUL
byte, and the complete canonical unsigned envelope. The recovery signer is
accepted only under the same-generation reload and manifest-selection rules
above. Its envelope binds environment, operation, root and transcript digests,
the root's exact admission start and checked 600-second deadline, exact last
stage and ordinal, reason, authority manifest/generation, role key, and one-use
nonce. It cannot select a target or effect. Its allowlisted reason
is one of `call_or_result_ambiguous`, `pre_effect_reauthentication_unconfirmed`,
`supervisor_stop_unconfirmed`, `source_stop_unconfirmed`,
`supervisor_remove_unconfirmed`, `source_remove_unconfirmed`,
`network_remove_unconfirmed`, `volume_preservation_unconfirmed`,
`post_teardown_reauthentication_unconfirmed`, `transport_cleanup_unconfirmed`,
`terminal_cleanup_unconfirmed`, `outcome_commit_unconfirmed`,
`deadline_expired`, `lock_lost`, or `fork_detected`.

Envelope consumption is exact-identity and one shot in process, then durable.
The recovery-intent record evidence has exactly
`recovery_classification_envelope_sha256`, `operator_nonce_sha256`,
`recovery_key_id`, `transport_authority_manifest_sha256`,
`classified_transcript_sha256`, `admission_started_boottime_ns`,
`operation_deadline_boottime_ns`, and `reason_code`. Both time values equal the
signed envelope/root and reproduce the checked sum. Once its STORE may have
begun, another envelope or nonce is forbidden. If the intent is exact and
durable after restart, only the deterministic outcome derived from that same
envelope and predecessor may be retained; the signer is not invoked again. If
intent retention is ambiguous, recovery may authenticate the one exact
content-addressed candidate and continue only with that same candidate. It may
not issue or accept a replacement classification.

The envelope's `transcript_sha256` and the intent's
`classified_transcript_sha256` must name the same published pre-intent snapshot.
The recovery-required outcome instead names the separately published final
snapshot whose last entry is that exact intent. Reusing the classified digest
as though it included the intent, omitting either file, or constructing a
transcript from an uncertain prefix permits no outcome write.

Unknown, mixed-version, conflicting, multiple-candidate, unstable, or
unreadable state permits no write at all and remains retention-unconfirmed for
manual incident preservation. Recovery uses no supervisor transport or Docker
mutation. Its fixed launcher can load only
`recovery-secrets/recovery-ed25519.raw` for the root-pinned generation and is
statically unable to name the host/supervisor encrypted blobs or tmpfs files.
It closes and exact-inode-unlinks a stale v2 socket only after proving no
listener and no live channel, then unlinks the exact recovery tmpfs inode and
zeroizes the recovery signer, nonce, and native buffers on every success,
failure, asynchronous, fork-child, and cleanup path. The tmpfs mount is
unmounted after owner cleanup. Recovery-required evidence grants no start,
re-arm, readiness, exposure,
broker, paper, live-trading, teardown, or deletion authority.

### State explicit invariants and fail-closed classifications

The implementation must preserve all of these invariants:

- exactly one fixed lifecycle/replay root exists across v1 and v2;
- one root binds one environment, operation, admission, topology, trusted head,
  transport generation, boot/process epochs, channel, exact admission-start
  sample, and checked 600-second deadline;
- one channel has exactly one signed request and exactly one signed result or
  error, with exact direction counters and no retransmission;
- request, result, and error signatures cover direction, schema, channel,
  boot/process epochs, the exact root-plus-intent lifecycle dispatch prefix,
  counter, deadline, and complete canonical payload;
- no operation frame precedes durable root and request-intent revalidation;
- every potentially effecting CALL has an exact durable intent, and no next
  intent precedes a separately authenticated durable result;
- the pre-effect and post-teardown observations are distinct one-shot issuances
  and distinct v2 bindings;
- the supervisor stops before the source, both containers are removed before
  the network, and neither named volume is a removal target;
- the same global lease spans admission, transport quiescence, effects,
  terminal cleanup, final transcript, and only then outcome commit, with no
  second flock and no reverse supervisor lock dependency;
- every registry rejects fork/process/thread substitution before locking;
- confirmed success requires ordinal 0 through 22 exactly, the published final
  prefix transcript whose first two entries recompute the signed dispatch
  prefix, and one committed ordinal-23 outcome; and
- every other state after possible root creation is recovery-required or
  retention-unconfirmed and never retry evidence.

Before possible root creation, path/symlink/permission drift, unknown or
overlapping key generations, private-key persistence outside the named tmpfs
mounts, signature failure, counter gap/reuse/wrap, boot/process/channel mismatch,
deadline equality, or success-relevant precommit cleanup failure closes the
fresh attempt. After possible root creation and before a fixed commit, the same
condition requires recovery. Post-confirmed-success-commit non-authoritative
registry/descriptor disposal is excluded from `cleanup failure`; it cannot invoke a fallback,
recovery writer, alternate outcome, or deadline path. No fallback algorithm,
endpoint, version, clock, key, decoder, or precommit cleanup path exists.

### Define the trust and threat boundaries

V2 is designed to reject replayed, duplicated, delayed, reordered, reflected,
cross-direction, cross-operation, cross-topology, cross-boot, cross-process,
cross-environment, truncated, oversized, or noncanonical frames; key-role and
generation confusion; local socket replacement; stale PID reuse; v1/v2
downgrade and mixed state; inherited locks/descriptors after fork; lifecycle
gaps and rewrites; effect-target substitution; volume deletion; and every
STORE/CALL/return ambiguity.

The trusted computing base remains the admitted Linux kernel and procfs,
`CLOCK_BOOTTIME` and `getrandom`, native owners/fork guard/zeroization, fixed
CPython launcher and dependency/image closure, filesystem and tmpfs mount
enforcement, offline transport-root and existing stop authorities, Docker
Engine and its root-owned Unix socket, provider and database identities, and
the host administrator. Compromise of the kernel, root account, Docker daemon,
offline roots, provider, database administrator, container runtime, or admitted
binary/image supply chain can violate the assumptions and is not eliminated by
repository evidence.

All v2 framed values are nonsecret, so passive disclosure is not a protocol
failure. Private endpoint and recovery keys are secret; their disclosure,
persistence outside the exact tmpfs custody, failure to zeroize, or role reuse
is a terminal admission failure and requires credential rotation before any
root exists. This ADR does not claim resistance to a malicious root
administrator reading process memory while an admitted signer is live.

### Roll out without migrating or partially activating v1

Implementation must use four reviewed, non-effecting milestones:

1. add independent v2 domain types, codecs, repository, ADR-0112 seam, fake
   transport/Docker adapters, and fault tests with zero production caller;
2. add the native endpoint, signer, fork guard, fixed launch profiles, key and
   mount admission, still with no real-root path or stop target;
3. compose all gates in an isolated injected-root environment against an
   isolated Docker daemon and disposable volumes, with `trusted-time-stop`
   unchanged; and
4. admit one immutable production release containing the complete composition,
   authorities, mount/image/executable receipts, integrated fault evidence, and
   operator review. No gate is enabled by an independent feature flag.

That future release must add the exact private read-write transport and
supervisor-secret tmpfs projections and prove private PID namespace plus
unremapped initial user namespace semantics in its effective Compose/topology
receipt. This design-only ADR intentionally does not edit today's Compose file;
the absent projections remain an activation blocker rather than an implied
current capability.

Before root creation, deployment rollback may remove the unreachable v2 code
and restore the previous hard-closed release. After a v2 root exists, software
rollback to a reader that cannot authenticate v2 is forbidden; the reviewed v2
recovery classifier must remain available. An exact v1 root continues to block
v2. No migration rewrites v1 or creates a v2 root from v1 evidence.

The current ADR-0110/0111 v1 modules, contracts, bytes, tests, and dormant
callers remain unchanged. The existing ADR-0112 public loader and v1-bound
private handoff remain unchanged; the v2 seam is additive and separately
guarded. Existing v1 decoders continue to reject v2, and future v2 decoders
reject every v1 value.

### Require implementation and activation evidence

Before any production caller exists, review must retain:

- canonical authority manifest/selection, process epoch, host hello, supervisor
  hello, host confirmation, channel, envelope, request, exact nested result,
  error, supervisor cleanup commitment, both quiescence receipts, root, every
  stage, transcript snapshot, outcome, commit, and recovery-
  classification vectors, including exact size/depth/node boundaries and the
  envelope formula at overhead/payload/packet `-1`, exact, and `+1`;
- signature tamper vectors for every signed field and complete payload,
  including a wrong root, request-intent, or derived lifecycle dispatch prefix,
  plus wrong role/key/generation/environment/direction, generation overlap, and
  root-signature failure;
- socket path, `0:10001:0770` transport tmpfs and read-write private projection,
  writable-listener positive proof, inode, owner/mode, symlink, forbidden GID/
  projection exposure, ancillary descriptor, truncation, disconnect, stale-path,
  and cleanup failures;
- boot/PID/start-time/namespace/channel mismatch, challenge substitution,
  counter duplicate/gap/rollback/wrap, process restart, suspend, clock
  regression, and equality-at-every-deadline tests, including host-side full
  supervisor PID/cgroup mapping and supervisor-side exact UID/GID `0:0`, PID-zero
  private-namespace acceptance with every nonzero/remapped variant rejected,
  plus bounded stable pre/post supervisor FD-table correlation for listener and
  accepted socket closure;
- fixed-publication timing vectors proving every five-second STORE/commit value
  and the 600-second operation value are prepublication authorization cutoffs,
  the exact admission-start sample occurs at the frozen pre-authority boundary,
  checked addition passes at `2^63-1 - 600_000_000_000` and rejects one above,
  root/admission/request-basis/final-request/candidate/marker/recovery values
  correlate and equality expires,
  equality rejects before protocol entry, ordinal-23 final authorization follows
  candidate readback/descriptor closure/empty-registry proof, only exact marker
  publication follows it, a recovery-required candidate carries and a confirmed-
  success candidate omits its final authorization sample, postpublication clock
  reads are non-authoritative, and timeout/crash at every marker step yields only exact-candidate/marker
  revalidation or `outcome_commit_unconfirmed` without dual outcomes;
- evidence that raw private credentials never enter Python, repository, image,
  environment, argv, log, persistent filesystem, lifecycle records, or core
  dumps, including the direct-preopened-tmpfs descriptor-one decrypt profile,
  no `LoadCredentialEncrypted` plaintext path, plus exact unlink and
  zeroization tests on ordinary, asynchronous,
  fork-child, terminal, and recovery paths, including kernel
  `MADV_WIPEONFORK` proof;
- selection-chain tests proving non-expiring manifest semantics, unique new-
  root selection, signed `new_roots_denied`, exact root-pinned historical
  verification, and null/mismatched recovery selection withholding every
  recovery write without relying on wall time;
- recovery-key tests proving exact encrypted-credential source and root-only
  tmpfs path/mode/UID admission, same-generation root/selection/public-key
  binding after restart, one-use envelope-to-intent consumption, exact-candidate
  continuation only, signer/file zeroization and unlink, and static/runtime
  inability to load host/supervisor keys, sign transport frames, open the
  transport channel, or call Docker;
- direct v1-to-v2 and v2-to-v1 negative vectors for contracts, bytes, objects,
  roots, prefixes, directories, receipts, binders, and adapted projections,
  plus an import/callgraph guard making ADR-0110/0111 unreachable from v2;
- concurrency and fault injection at every root/record/outcome STORE, transport
  send/receive, external CALL, result STORE, cleanup, and return, proving one
  root, one result, no replay, and the exact ambiguity classification;
- signed-wire artifact vectors proving the complete received canonical result
  or error envelope bytes (including payload and signature) are the immutable
  file bytes, ordinary full-envelope SHA-256 selects the literal final name,
  exclusive/no-follow staging, file/directory fsync, no-replace rename, stable
  readback/re-encode/signature verification and publication receipt all agree,
  ordinal-two evidence binds every envelope/payload/schema/key/channel/lifecycle-
  dispatch-prefix/counter/deadline identity, and payload-only, digest-only,
  orphan, pair, conflict, or interrupted publication is retention-unconfirmed;
- transcript vectors proving exact root/progress nesting, domain digest,
  content-addressed name, classified-prefix versus final recovery transcript,
  exact non-circular request-basis to ordinal-one-intent to dispatch-prefix
  construction, dispatch-prefix domain/object derivation from stable ordinal
  zero/one,
  every later transcript's matching first two entries, wrong-root/intent/prefix
  rejection, fsync/no-replace-rename/readback publication, staging/conflict
  rejection, and deterministic outcome/recovery use;
- an event trace proving one global lease spans channel preflight, four-way
  fresh admission, root reservation, every state transition and effect,
  transport quiescence, both reauthentications, terminal cleanup, final
  transcript, and terminal commit, followed by a separately classified
  post-commit trace proving empty registry disposal and kernel-guaranteed lease
  release cannot call lifecycle/recovery/outcome/deadline code;
- fork-child, wrong-process, wrong-thread, PID-reuse, inherited-owner,
  inherited-mutex, seccomp, and asynchronous-exception tests proving checks
  occur before locks and descriptors close before child registry use;
- method-surface and fake-daemon proofs for every literal `/v1.45` method/path,
  ordered query, fixed request headers, absent request body, and intent/result/
  trace digest; response vectors cover HTTP version/status/header/framing limits,
  exact Content-Length and 204 zero body, prohibited chunking/truncation, every
  endpoint body ceiling, exact container/network 404 JSON, duplicate/deep JSON,
  every typed projection and closed missing/null normalization, explicit
  unknown-raw-field ignoring with raw-body
  digest retention, query reordering, omitted or true delete flags, explicit
  stop signal, abbreviated/escaped IDs, and ambiguity; canonical connection-
  identity vectors cover mount/path/device/inode, peer UID/GID/PID and daemon
  process, bounded `/proc/<pid>/stat` field-22 parsing, actual executable-byte
  hashing with stable `fstat`, bounded/stable cgroup bytes, local socket inode/
  device/`SO_COOKIE`, capture/revalidation points, digest domain, and rejection
  of raw-FD substitution or identity drift; exact
  admission vectors cover the literal six-read order and complete ordered
  request/connection/exchange/trace digest lists; exact result vectors cover
  every closed container-stop/container-remove/network-remove/volume-proof
  object, complete nested exchange/identity/trace objects and parallel digests,
  semantic domain/digest, connection
  ordinals `0..17`, zero `/volumes` DELETE and zero container-delete volume-
  removal reachability, and both unchanged volume projections;
- isolated integration evidence for exact supervisor-first/source-second stop,
  per-ID removals, network removal, volume preservation, distinct pre/post
  ADR-0109 issuers and bindings, transport quiescence at ordinal four, terminal
  cleanup at ordinal twenty-two, success only at ordinal twenty-three, and
  success-relevant precommit cleanup failure producing no success and no effect
  continuation;
- recovery vectors for every exact prefix, staging/commit interruption, signed
  classifier replay, unknown/mixed/conflicting state, and proof that no
  recovery path can reach transport dispatch or Docker mutation; and
- independently approved authority provisioning, fixed executable/image/import
  manifests, exact tmpfs and private read-write projection receipts,
  Docker/provider/database
  identities, operational drill, and branch-protection evidence before the
  hard-closed Make target may change.

### Keep the non-goals closed

V2 does not seek transport confidentiality, non-Linux portability, reconnect or
high availability, more than one permanent stop attempt, effect retry or
compensation, recovery continuation, a generic Docker API, Compose control,
volume-content attestation, v1 migration, ordinary transport-root rotation, or
automatic operational activation. It does not redesign ADR-0108/0109 source
semantics, ADR-0112's existing v1 consumers, Docker's trust boundary, or the
host-administrator threat model. Any such change requires a successor decision
and cannot be inferred from an implementation milestone.

### Keep current authority and runtime surfaces absent

This ADR adds documentation only. It creates no key, signature, credential,
authority manifest, tmpfs mount, socket, process, registry, lifecycle artifact,
root, outcome, migration, Docker call, provider/database call, network access,
CLI, Make target, or production importer. It does not inspect or mutate the
real artifact root or external environment.

It grants no stop, signal, teardown, recovery-effect, start, restart, re-arm,
readiness, exposure, broker, paper-trading, or live-trading authority. The
future recovery classifier may retain only the deterministic recovery-required
classification for a known uncommitted prefix or revalidate/finalize the one
already-created exact outcome candidate whose fixed commit alone is uncertain,
including a confirmed-success candidate with an authenticated exact fixed-
marker staging/final preimage that proves both precommit authorization cutoffs
were passed. It may never create a new success candidate, continue an effect,
or infer confirmed-success authorization from the candidate alone. This ADR does not provision
its key or implement its writer. The design is not an operator procedure.

`make trusted-time-stop` remains the exact no-prerequisite two-line hard-close.
It prints
`trusted-time-stop is approval-blocked: no effecting approved shutdown operator is implemented`
to standard error and exits 2 without invoking Python or Docker.

## Consequences

The implementation team now has one concrete target instead of a list of
security-sensitive choices. Transport origin, endpoint binding, key custody,
rotation, counters, boot/process identity, deadlines, schemas, root semantics,
historical handoff, lock order, fork behavior, effect methods, volume proof,
both reauthentication boundaries, and recovery disposition are all fixed.

The design is intentionally restrictive. It supports one Linux deployment,
one global stop attempt, one active key generation, one request/result exchange,
one exact effect order, and no continuation after ambiguity. That makes a
partial implementation less useful operationally, but preserves the central
invariant that no missing result can become retry or success evidence.

No runtime behavior changes. All implementation, provisioning, integration,
deployment, and operational evidence remains ahead, and the stop target stays
hard closed.

## Rejected alternatives

- **Use a local stream socket, stdout, Docker exec, or peer credentials alone.**
  None supplies exact bounded messages plus independent cryptographic origin
  and replay binding.
- **Encrypt all transport frames.** The fields are deliberately nonsecret.
  Encryption adds nonce/key-agreement state without strengthening the required
  integrity/origin property; a confidential successor requires a new version.
- **Use one shared HMAC key.** Either endpoint could forge the other direction,
  and rotation/custody could not prove role separation.
- **Persist endpoint keys under `/opt`, an artifact root, image, or volume.** A
  restart or filesystem reader could recover credentials outside the named
  ephemeral custody boundary.
- **Accept overlapping key generations.** A grace window creates two valid
  transport identities for one operation and weakens replay classification.
- **Use wall time or `CLOCK_MONOTONIC`.** Wall time can step, and ordinary
  monotonic time excludes suspend on Linux. `CLOCK_BOOTTIME` supplies one
  shared suspend-aware kernel domain.
- **Reset counters after reconnect.** A reconnect is a different challenge,
  process/channel identity and, after reservation, is forbidden entirely.
- **Create a new v2 root beside ADR-0110 v1.** Two permanent roots make the
  replay domain ambiguous. The fixed filename is the one global slot.
- **Extend or migrate the v1 root.** That changes retained evidence meanings
  and permits version confusion.
- **Reuse the current ADR-0112-to-ADR-0111 handoff.** Its capability is bound to
  the v1 bridge identity. The additive v2 consumer shares source
  authentication, not v1 bridge state.
- **Acquire a supervisor flock or repository flock under the host lock.** A
  reverse acquisition path could deadlock while the controller waits for the
  result. The supervisor never attempts the global flock and v2 adds no second
  cross-process lock.
- **Use Python-only at-fork cleanup or check PID after locking.** The child can
  deadlock or act on an inherited descriptor before reaching that code.
- **Use Docker CLI or Compose for effects.** Process creation violates the live
  fork boundary, and generic command surfaces can retarget by name or delete
  volumes.
- **Infer a successful effect from later stopped/absent state.** A lost return
  remains ambiguous even when the desired state is later observed.
- **Reuse the pre-effect observation after teardown.** It predates every
  effect and cannot authenticate the terminal head or provider state.
- **Continue a fully result-confirmed prefix after restart.** The original
  lease, process/thread/channel, deadlines, and one-shot bindings are gone.
  Recovery classifies and preserves; it never resumes.
- **Wire the design to `trusted-time-stop`.** Documentation resolution is not
  implementation, deployment evidence, or operational authority.
