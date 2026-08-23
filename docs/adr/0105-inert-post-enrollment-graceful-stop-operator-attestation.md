# ADR 0105: Inert post-enrollment graceful-stop operator attestation

- Status: Accepted for code-only public authentication; stop admission and
  shutdown effects remain absent
- Date: 2026-08-15
- Extends:
  [ADR 0104](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

ADR 0104 retains enough immutable start evidence to construct one exact
graceful-stop target and freezes a distinct one-attempt stop decision. That
decision is deliberately unsigned and reports that external attestation is
required. Reusing the post-enrollment-start authority, key identity, statement,
envelope, verifier, or replay domain would allow one protocol's bytes to be
misinterpreted in another. Treating a signature as a currentness or effect
admission proof would also skip the still-missing checks over the committed
start outcome, start attempt slot and envelope, live Docker topology, trusted
head, replay state, and clean-stop successor.

The repository therefore needs a complete but inert public authentication
chain for the graceful-stop decision. It must let an operator prepare public
authority bytes and exact statement bytes, verify a detached public signature,
and retain a content-addressed envelope without importing any private key or
enabling shutdown. The real stop authority remains an independently reviewed
source change and is intentionally absent in this code-only slice.

## Decision

### Use a distinct stop authority and require key separation at installation

Freeze a dedicated public authority manifest with contract
`phase6d-post-enrollment-graceful-stop-operator-attestation-authority-v1`,
service
`trusted-time-post-enrollment-graceful-stop-operator-attestation-authority`,
status `public_graceful_stop_operator_authority_material`, algorithm
`Ed25519`, key ID
`aqt-post-enrollment-graceful-stop-operator-ed25519-v1`, and replay domain
`github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-graceful-stop/operator-attestation/v1`.
Its exact eight fields are `algorithm`, `contract_version`, `key_id`,
`public_key_base64`, `public_key_sha256`, `replay_domain`, `service`, and
`status`.

The raw public key is exactly 32 bytes and must be a canonical compressed
Edwards25519 encoding of a non-identity point in the prime-order subgroup.
Identity, torsion, mixed-subgroup, noncanonical, and off-curve encodings are
rejected before publication and independently before verification. The
manifest is bounded to 4 KiB and has one compact newline-terminated canonical
JSON representation.

The fixed future source path is
`infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-authority.json`.
It is absent in this slice. Preparing an external candidate does not require an
installed start authority and reports that distinct-start-key review remains
required. Installing the stop authority is stricter: it must load and
revalidate the exact fixed post-enrollment-start authority, compare canonical
public-key digests, and reject absence, ambiguity, or equality. A stop
authority therefore cannot be installed first or silently reuse the start
public key. Installation still authorizes and executes nothing.

### Sign one exact stop-decision statement

Freeze one statement contract
`phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1`,
service `trusted-time-post-enrollment-graceful-stop-operator-attestation`, and
status `exact_one_attempt_graceful_stop_decision_statement`. Its exact fields
are:

- `algorithm`;
- `authority_artifact_sha256`;
- `authority_contract_version`;
- `contract_version`;
- `decision`;
- `graceful_stop_decision_contract_version`;
- `graceful_stop_decision_v1_sha256`;
- `graceful_stop_operation_id`;
- `graceful_stop_target_sha256`;
- `key_id`;
- `public_key_sha256`;
- `replay_domain`;
- `service`; and
- `status`.

The decision is exactly `approve_one_post_enrollment_graceful_stop_attempt`.
Plain Ed25519 signs the complete compact newline-terminated canonical statement
bytes, not a digest and not Ed25519ph. The statement repeats the distinct stop
operation UUID and target SHA from the exact decision so a verifier can bind
the signed identity without importing an effecting stop implementation.

Freeze one envelope contract
`phase6d-post-enrollment-graceful-stop-decision-v2`, service
`trusted-time-post-enrollment-graceful-stop`, and status
`operator_attested_graceful_stop_decision_envelope`. Its exact nine fields are
`contract_version`, `graceful_stop_decision_v1_base64`,
`graceful_stop_decision_v1_sha256`, `operator_attestation_statement`,
`operator_attestation_statement_sha256`, `service`, `signature_algorithm`,
`signature_base64`, and `status`. It preserves the exact canonical v1 decision
bytes and one raw 64-byte signature. The 256 KiB envelope bound accommodates
the complete 128 KiB decision projection without truncation. There is no v1
auto-wrap, unsigned fallback, alternate signature encoding, or cross-protocol
translation.

The dependency-pure codec validates canonical byte and digest relationships
and the frozen top-level decision identity. It does not import the structural
graceful-stop bridge under `scripts/` and does not independently establish the
decision's full target semantics. The offline workflow performs that semantic
decode and exact re-encode before producing statement bytes.

### Verify only public authentication facts

The explicit-authority Ed25519 verifier accepts only the dedicated stop
authority and stop envelope types. It independently validates the public point,
canonicalizes and decodes one isolated snapshot, verifies the signature over
the exact statement bytes, and cross-checks the authority, public-key, decision,
operation, target, statement, signature, and envelope identities.

Its sealed result uses contract
`phase6d-post-enrollment-graceful-stop-operator-attestation-verification-v1`,
service
`trusted-time-post-enrollment-graceful-stop-operator-attestation-verification`,
and status `graceful_stop_operator_signature_authenticated_unqualified`.
That status reports only public signature and exact-byte authentication. The
result is `verification_only=true`; decision, target, currentness, freshness,
single use, stop admission, signaling, removal, teardown, retry, operational
control, broker, paper, and live-trading facts and authorities all remain
false. Direct construction, subclassing, mutation, copying, dataclass
replacement, and pickle round trips cannot forge a usable result.

### Keep authoring offline and public-only

The public authority provisioner has separate `prepare` and `install` phases.
It accepts only an explicit absolute owner-only raw public-key file or reviewed
content-addressed candidate. The detached-attestation workflow has separate
`prepare-statement` and `verify-signature` phases and accepts only explicit
absolute owner-only authority, decision, statement, raw-signature, and output
paths plus reviewed SHA-256 values. It semantically decodes and exactly
re-encodes the v1 graceful-stop decision before statement publication and
reopens and revalidates every input before retaining an authenticated envelope.

All external input and output directories are pre-existing, current-user-owned,
mode-`0700` directories outside the repository. Inputs are bounded single-link
regular files with mode `0400` or `0600`. Candidates are mode `0600`,
content-addressed, exclusively created, file- and directory-fsynced, read back,
and rebound to the final named path before a receipt is returned. Exact
idempotent retries preserve the inode and bytes; conflicting or ambiguous
retention fails closed without unlinking possible evidence.

The workflows accept no private key, seed, signer, generator, environment-file
or standard-input key channel, network, database, Docker, Compose, controller,
admission, host-orchestrator, runtime, clock, or randomness authority. Public
receipts expose only basenames or the fixed public install path, public digests,
fixed identities, and explicit false qualification and operational-authority
fields. The provisioner/offline workflow scripts and fixed manifest are
excluded from Docker build contexts;
the public codec and verifier modules contain no secret material or runtime
caller.

### Keep the runtime boundary closed

This ADR adds no installed authority, mutable-worktree authority loader,
reviewed-Git-object runtime loader, current-topology or trusted-head verifier,
stop-attempt slot, stop admission, stop outcome/recovery protocol, controller
or host caller, signal sender, Docker action, CLI executor, or effecting Make
target. `make trusted-time-stop` remains a no-prerequisite, two-line failure
that invokes no Python or Docker command.

ADR 0106 now supplies the separate supported `prepare-decision` command. It
reloads and revalidates the committed confirmed outcome v2, locator, exact
current-v3 start-attempt slot, and signed start envelope before publishing one
content-addressed decision-v1 candidate. Its expected-digest flags are review
assertions against artifact-derived identities, not decision authority. The
ADR-0104 in-memory builder remains a non-operational structural projection when
called outside that binder; an operator must not manufacture a raw tuple.

Before any shutdown effect, a later atomic admission design must reload and
semantically authenticate the committed confirmed controller-outcome v2 and
locator, exact v3 start attempt slot and start attestation envelope, exact stop
decision and envelope, and the stop authority Git blob from the target's
approved revision. It must then establish fresh topology and trusted-head
evidence, reserve a distinct permanent stop-attempt slot, define durable stop
outcome and recovery semantics, and revalidate the entire chain immediately
before signaling the exact supervisor container. Signature verification alone
is never admission.

ADR 0111 now includes the operator-attestation-envelope digest in its canonical
operation-bound request, but deliberately reports
`operator_attestation_authenticated=false` and
`stop_decision_authenticated=false`. Its host builder receives no reviewed-Git
stop-authority loader and cannot turn the digest into admission or effect
authority.

## Consequences

Given an exact ADR-0106 decision-v1 candidate, the repository can construct its
statement/envelope and publicly verify the external signature without gaining
private signing authority or a shutdown capability. Protocol identity and
installation-time key separation prevent the start and stop trust roots from
being silently conflated. Missing real public material and the absent
currentness, stop replay, admission, outcome/recovery, and effect layers keep
every operational path fail closed.

This adds another deliberately narrow offline workflow and more public digest
review. Any future key rotation needs a new reviewed key identity and explicit
cutover rules; the v1 manifests are not mutable registries.

## Rejected alternatives

- **Reuse the start authority manifest or key.** Its key ID, replay domain, and
  decision are start-specific, and shared raw key material couples compromise
  and rotation. Stop installation therefore requires a distinct public key.
- **Sign the full decision envelope directly or sign its digest.** A small,
  domain-separated canonical statement makes the intended bytes explicit and
  avoids Ed25519ph or implicit-prehash ambiguity while still binding the exact
  decision and target.
- **Treat a valid signature as currentness or stop authority.** The signed
  target is historical review evidence until live topology, trusted head,
  replay, and durable recovery are independently proven.
- **Add a repository signer or private-key input.** The external operator
  system remains the only private-key custodian.
- **Install a placeholder public key.** Absence must remain a visible,
  fail-closed operational prerequisite.
- **Wire `trusted-time-stop` now.** No stop slot, currentness proof, clean-stop
  proof, durable outcome, or recovery protocol exists yet.
