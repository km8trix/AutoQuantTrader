# ADR 0111: Dormant operation-bound clean-stop supervisor bridge

- Status: Accepted for code-only, unqualified operation/result correlation and
  same-process terminal composition; no production caller, transport,
  lifecycle advance, stop outcome, or shutdown effect exists
- Date: 2026-08-17
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md),
  [ADR 0105](0105-inert-post-enrollment-graceful-stop-operator-attestation.md),
  [ADR 0106](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md),
  [ADR 0107](0107-fail-closed-clean-stop-completion-invariant.md),
  [ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md),
  [ADR 0109](0109-code-only-clean-stop-terminal-reauthentication.md),
  and
  [ADR 0110](0110-dormant-durable-graceful-stop-lifecycle-repository.md)
- Extended by:
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)

## Context

ADR 0110 stops at ordinal one,
`operation_bound_supervisor_bridge_required`. It deliberately cannot construct
a post-signal stage or confirmed stop outcome until one exact stop operation is
bound to both the in-process ADR-0108 result and a one-shot ADR-0109 terminal
reauthentication.

Those inputs live on different trust boundaries. ADR 0108 seals one exact
current-request result inside the supervisor process, but object identity
cannot cross a process boundary. ADR 0109 seals one bounded host-side
SQL/provider/SQL observation, but it contains no stop operation, attempt root,
progress prefix, or supervisor request identity. A generic `clean_stop`, a
boolean close result, stdout, process exit, or a caller-supplied digest cannot
join them safely.

The request must exist before the worker selects its `CLEAN_STOP` work. A
request added after selection or completion would permit post-hoc relabeling.
The worker request is also a frozen dataclass only by ordinary API; coordinated
`object.__setattr__` mutation can change its scalar fields. Capturing those
fields after a callback would let a relabeled work request become the new
authority. Likewise, copying live ADR-0108 fields before one-shot export would
permit an ABA mutation to create a mixed terminal projection.

This slice closes those code-level correlation gaps without claiming that the
wire came from the supervisor, that the stop evidence is current, that the
ADR-0110 lifecycle advanced, or that any external effect is safe.

## Decision

### Freeze a strict structural request and result wire

Application module
`packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py`
defines service `trusted-time-head-anchor-clean-stop-supervisor-bridge` and two
separate canonical contracts:

- request contract
  `phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-request-v1`,
  status `operation_bound_clean_stop_requested_unqualified`; and
- result contract
  `phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-result-v1`,
  status
  `exact_operation_bound_new_record_clean_stop_correlated_unqualified`.

The exact request binds:

- the graceful-stop operation, target, decision-v1, and structural
  decision-artifact-receipt SHA-256 values;
- the stop operator-attestation envelope SHA-256;
- the ADR-0110 attempt-slot and bridge-required-progress SHA-256 values;
- the retained controller outcome and durable shutdown locator SHA-256 values;
- the active-controller session, persistent-topology, and topology-transcript
  SHA-256 values; and
- the exact supervisor container ID.

Its checkpoint reason is `clean_stop`, `exact_new_record_required=true`, and
its exact progress binding is ordinal one and phase
`operation_bound_supervisor_bridge_required`. The request is structural and
unqualified. In particular, the decision-artifact-receipt digest is not a
durably reloaded ADR-0106 receipt authentication fact.

The result embeds the complete canonical request plus its SHA-256 and carries
the exact ADR-0108 terminal projection: worker sequence and scheduled monotonic
instant; anchor sequence, predecessor, confirmed and local counts, and terminal
ordinal; current head, anchor-byte SHA-256, anchor semantics, intent, readback, and
receipt identities; receipt UTC; audit and prior-recovery facts; exact-one
upload/duplicate counts; and the recomputed ADR-0108 terminal semantic
SHA-256. Its one positive fact is
`exact_request_work_result_correlated=true`. That is an unqualified structural
correlation, not transport, currentness, durability, outcome, or effect
authentication.

The 64-KiB request and 128-KiB result codecs accept only exact canonical JSON
with one trailing newline. Decoders reject duplicate keys at every nesting
level, floats, non-finite values, booleans used as integers, oversized
integers, excessive depth or node count, unknown or missing fields,
noncanonical bytes, and size overflow. They reconstruct and re-encode the
complete value before accepting it. A decoded value proves only that bytes
match the frozen schema; it does not authenticate transport or origin.

Both classes are exact-type, slotted, identity-comparing, noncopyable,
nonreplaceable, and nonserializable through pickle. The result is issued or
decoded only through a private construction capability. Its terminal semantic
digest is recomputed from all nineteen ADR-0108 fields rather than accepted as
an arbitrary lowercase digest.

### Bind before selection and issue before completion clears

`TrustedTimeHeadAnchorWorkerCore` gains only private operation-bound methods.
The private request path registers the exact request and core before setting
`_clean_stop_requested`. Registration is single use by request digest and
captures the exact control-thread object. An unseen exact decoded request may
be the first registered object; that remains structural and does not
authenticate its transport. Once registered, a decoded, copied, or scalar-equal
substitute cannot replace the exact object, and that attempted digest cannot be
registered again. Post-selection, cross-core, post-fork, old-completed, and
previously attempted associations reject.

When the core selects the new `CLEAN_STOP` work, it derives this immutable
five-field tuple from constructor locals before publishing `_in_flight`:

1. request sequence;
2. checkpoint reason;
3. full-audit flag;
4. allow-enrollment flag; and
5. scheduled monotonic instant.

The binder requires the exact `TrustedTimeHeadAnchorWorkRequest` object, exact
core, exact pending request, exact in-flight state, and that supplied tuple.
It rechecks the live work projection after capturing the exact worker-thread
object, then stores the supplied tuple rather than values observed after a
callback. Issue and take both require the same work identity and unchanged
five-field tuple.

After the normal ADR-0108 worker consume, and before `_in_flight` is cleared,
the bridge performs a distinct second one-shot ADR-0108 export. That export
atomically removes the exact registry entry before detailed validation and
returns the immutable registered nineteen-field projection plus its semantic
SHA-256. The bridge result is constructed only from that returned snapshot. It
does not read live terminal fields afterward. The unchanged full five-field
work tuple is required separately. The exact attempt result must match the
captured sequence, reason, full-audit implication, and every field it shares
with the returned ADR-0108 terminal projection; it does not itself carry the
work schedule or allow-enrollment flag.

Invalid bind, issue, export, take, wrong-core, wrong-thread, wrong-identity,
early, process-local association replay, drift, asynchronous, and validation
paths burn the exact association before reporting failure. PID checks precede
every registry lock,
including weak-reference cleanup, so a forked child rejects instead of waiting
on an inherited lock. `KeyboardInterrupt`, `SystemExit`, and other asynchronous
`BaseException` values are preserved after cleanup; ordinary failures become
fixed domain errors.

The issued registry retains the exact result identity, immutable field tuple,
canonical bytes, and byte digest. The core's private one-shot take validates
the exact stopped core, original control thread, unchanged work projection,
and issued seal, then returns the already captured canonical bytes rather than
the mutable object. Every operation-bound creation, success commit, and take
is guarded through its return boundary. Interruption cannot strand a live
registry association or expose bytes from a partially committed transition.

The existing generic `request_clean_stop` path never registers, binds, issues,
or returns an operation-bound bridge result. Existing supervisor main and
background close behavior remain unchanged.

### Cross-bind one host observation without turning it into an outcome

Dormant host module
`scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py`
defines contract
`phase6d-post-enrollment-graceful-stop-supervisor-bridge-v1`, service
`trusted-time-post-enrollment-graceful-stop-supervisor-bridge`, and status
`operation_bound_terminal_projection_cross_bound_unqualified`.

Its public request builder accepts only the exact process-local ADR-0106
decision-artifact receipt and exact retained ADR-0110 attempt and ordinal-one
progress receipts. It repeatedly reloads and revalidates the retained attempt
and progress from one explicitly injected ignored root, snapshots each source,
and requires all operation, target, decision, envelope, locator, controller,
topology, progress, and supervisor bindings to agree. Because ADR 0106 has no
durable receipt input in this composition, the supplied receipt and its digest
remain process-local structural inputs. ADR 0112 later adds a zero-caller
inert loader, explicit fresh authenticator, and consuming revalidator for the
exact durable receipt projection, but this builder does not consume its
authenticated loaded wrapper. It is still not a historical receipt recovery
path.

The public terminal binder creates one private bridge identity and consumes the
exact ADR-0109 postcondition before later validation. The ADR-0109 consumer
returns its immutable registered projection, issuer identity, and bridge
identity; a wrong result, issuer, bridge, thread, process, mutation, or second
attempt burns the observation. The binder then captures and strictly decodes
the low-level request and result wire, revalidates the ADR-0110 evidence chain,
and requires the ADR-0108 result and ADR-0109 postcondition to agree on the
anchor sequence, reason, counts, terminal ordinal, predecessor, current head,
signed-record byte digest and semantics, intent, readback, receipt, and receipt
UTC.

The returned
`TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation` is a
same-process, process/thread-bound, registry-sealed composite. Its only
positive facts are:

- `provider_terminal_observed_under_stable_sql_authenticated=true`, preserving
  ADR 0109's bounded point-in-time observation; and
- `exact_terminal_projection_cross_bound_unqualified=true`, reporting that the
  exact thirteen terminal fields shared by the structural ADR-0108 result and
  consumed ADR-0109 snapshot matched.

The second fact deliberately contains `unqualified`. Even the first remains
only ADR 0109's observation interval, not lasting currentness. The composite's
decision-receipt authentication, historical-chain authentication, low-level
request/work/result qualification, transport and origin authentication,
currentness, freshness, topology, lifecycle, durability, single use for an
effect, slot reservation, admission, signal, teardown, outcome, recovery,
operational, and trading facts are false. Its payload and semantic digest are
inspectable only while every exact source object and consumed registry snapshot
remain valid; there is no public composite decoder, persistence format, or
effect consumer.

### Keep the complete composition dormant

No production code calls the worker's private operation-bound request or take
methods. The host builder and binder do not import those private core or
registry seams. There is no process transport connecting the host's canonical
request bytes to the supervisor, no authenticated result channel returning the
captured bytes, and no production caller of the host bridge.

This slice adds no application main or background-worker integration, signal
handler, CLI, Make target, Docker or Compose command, subprocess, socket,
provider or SQL operation, lifecycle writer, topology mutation, container or
network removal, outcome retention, recovery executor, watchdog consumer, or
shutdown effect. `make trusted-time-stop` remains the exact hard-closed target
that exits 2 without invoking Python or Docker.

The following work remains explicitly deferred:

1. explicit authentication and integration of ADR 0112's exact loaded ADR-0106
   decision-artifact receipt into this operation-bound host request, with
   consuming revalidation at the reviewed use boundary;
2. an authenticated, bounded, replay-safe host-to-supervisor request/result
   transport with explicit origin identity and failure semantics;
3. same-lock current topology, stop-authority, and operation admission that
   binds the live topology lease to the request before reservation or effect;
4. a separately versioned lifecycle successor to ADR-0110 v1 that can retain
   the bridge result, pre-CALL intents, authenticated post-CALL results,
   confirmed success or recovery-required terminal, and every CALL/STORE
   ambiguity without rewriting the immutable v1 prefix;
5. explicit at-fork invalidation and inherited-lock cleanup for every live
   core, host-composite, ADR-0109, and lifecycle registry before a process that
   can fork may construct them; and
6. the reviewed supervisor signal, source stop, exact container/network
   teardown, named-volume preservation, terminal reauthentication, and durable
   outcome choreography.

Canonical wire bytes and process-local one-shot seals do not close any of
those deferrals.

The architecture boundary also pins one exact raw-source-byte manifest over
every regular Python file below `apps`, `packages`, and `scripts`, including
the checker itself. `apps/web/node_modules` is the sole lexical prune; it is a
third-party vendor tree and contains no reviewed first-party Python source.
Every symlink outside that exact prune is rejected, as are source additions,
removals, renames, parse failures, and byte changes. Native extension artifacts
(`.so`, `.pyd`, `.dylib`, and `.dll` families), legacy sourceless bytecode, and
source or native artifacts hidden inside `__pycache__` are rejected throughout
the reviewed roots. All `.pyc` and `.pyo` files are rejected, including direct
`__pycache__` entries; ignored or transient bytecode is not a trust exception.
A separate path-framed raw bootstrap manifest pins `.python-version`,
`pyproject.toml`, `uv.lock`, the exact hashed native build-constraint closure,
the executable-image manifest helper, the exact Hatch native hook, and its C
source and rejects alternate local build configuration before PEP-517 may execute. The
authoritative Make and CI flows set a non-overridable
`PYTHONDONTWRITEBYTECODE=1`, run the project-independent checker before any
project sync/build/import gate, repeat it after installation/native packaging,
and keep caches absent afterward.

Repository and CI bootstrap must use
`uv run --isolated --no-project --no-config --offline --no-python-downloads --python 3.12 python -I -B scripts/check_architecture.py`. Project/config discovery, environment reuse, network Python
download, workspace/`PYTHONPATH` imports, and bytecode writes are disabled. Run
this command directly before invoking Make on an unreviewed checkout, because
Make parses repository bytes before entering its architecture recipe. CI uses a
standalone architecture prerequisite job before backend/native work and repeats
the exact command after sync and build.

The prune is not a generic authentication claim about dependencies:
`node_modules`, the interpreter standard library and startup hooks such as
`sitecustomize`, and ordinary third-party `site-packages` remain trusted
environment inputs. The private native owned-descriptor extension is outside
that exception and requires its exact source/build/origin/byte/image-manifest
and read-only/noexec runtime admission. The selected interpreter and standard
library remain trusted inputs, not evidence authenticated by this ADR.
The complete Makefile and CI workflow bytes are separately pinned so skip,
ignore-error, shell, environment, relocation, and target-reachability changes
fail review. GitHub workflow execution and required-check branch protection
remain external trusted controls; the repository pin cannot prove that a host
actually ran the workflow or enforced its result.

## Consequences

The repository can now express and test the exact missing correlation: one
preselected stop operation can be bound to one exact worker request, one exact
new-record ADR-0108 result, and one one-shot ADR-0109 host observation without
accepting scalar clones, post-hoc registration, field drift, process-local
association or postcondition replay, forked state, or asynchronous partial
commit. The structural wire itself remains replayable; replay-safe transport is
explicitly deferred.

That result is intentionally dormant and unqualified. It does not advance the
ADR-0110 lifecycle, authenticate its own transport, prove current topology or
lasting provider terminality, reserve a real attempt, or authorize any stop
effect. No production stop was executed and no real lifecycle artifact was
created while accepting this ADR.

Future work must compose the deferred loaded evidence, transport, admission, lifecycle
successor, at-fork behavior, and effects as one reviewed ordering. Exposing the
private core methods, treating decoded bytes as issued evidence, or wiring the
host builder alone would reopen the exact identity and ambiguity gaps this ADR
closes.

## Rejected alternatives

- **Register after the worker selects `CLEAN_STOP`.** That permits an old or
  unrelated result to be relabeled for a later operation.
- **Bind only scalar-equal request or work fields.** Independent cores and
  mutable frozen objects can carry the same or later-restored scalars.
- **Copy live ADR-0108 fields into the result.** ABA mutation can mix values
  unless the second consume returns and owns the immutable registered snapshot.
- **Return the issued object from the core.** Returning captured canonical
  bytes prevents later object drift from changing the already-taken result.
- **Treat canonical decoding as transport authentication.** Canonical bytes
  prove syntax and exact content only, never who sent them or whether they are
  current.
- **Persist or serialize the host composite.** Its guarantees depend on exact
  same-process objects, thread identity, and consumed registries.
- **Advance ADR-0110 v1 directly.** That contract has no ordinal-two,
  post-signal, or confirmed-success schema; a new reviewed lifecycle version is
  required.
- **Wire `trusted-time-stop` now.** Loaded-receipt integration, transport,
  topology admission, lifecycle successor, at-fork protocol, and all effects
  remain absent.
