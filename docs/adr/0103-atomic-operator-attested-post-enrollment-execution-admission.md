# ADR 0103: Atomic operator-attested post-enrollment execution admission

- Status: Accepted (code-only v3-only admission and host composition
  implemented; fixed authority absent and no execution performed)
- Date: 2026-08-15
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0100](0100-post-enrollment-operator-public-key-provisioning.md),
  [ADR 0101](0101-inert-post-enrollment-operator-attestation-verification.md),
  and
  [ADR 0102](0102-offline-post-enrollment-operator-attestation-artifacts.md)

## Context

ADR 0099 implemented a code-only one-shot post-enrollment start around an
unsigned canonical v2 approval. ADR 0100 froze an installable public authority,
ADR 0101 froze an exact signed statement and v3 envelope, and ADR 0102 added an
offline public-artifact workflow. Those slices deliberately left the v3
envelope unreachable from execution.

Adding only a verifier call to the old host would be unsafe. It could leave an
unsigned-v2 downgrade path, trust mutable working-tree authority bytes, lose
attestation identities at the permanent attempt slot, or validate a signature
before reservation but not again at the last pre-mutation boundary. The cutover
must therefore replace the complete execution-facing approval path atomically
while preserving every historical consumed attempt.

## Decision

The post-enrollment execution path is v3-only. Contract
`phase6d-post-enrollment-start-host-orchestrator-v3` accepts one explicit
content-addressed operator-attested approval artifact and one owner-only runtime
environment file. Its sole public entry is
`run_operator_attested_post_enrollment_start_once`, with exact keyword inputs
`operator_attested_approval_artifact` and `runtime_env_file`. The isolated CLI
uses `allow_abbrev=False` and exposes only
`--operator-attested-approval-artifact` and `--runtime-env-file`. The former
`run_approved_post_enrollment_start_once` entry, `--approval-artifact` flag, and
unsigned-v2 execution fallback do not exist.

### Exact reviewed authority and v3 load

`load_post_enrollment_operator_attested_execution_approval` returns only an
exact `LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval`. It
accepts an external owner-only, content-addressed
`trusted-time-post-enrollment-start-execution-approval-v3-<sha256>.json`
artifact and performs the complete load before Docker qualification, issuer
creation, runtime-input materialization, reversible diagnostics, attempt
reservation, or topology mutation.

The loader:

1. canonically decodes the v3 envelope and fixes its content-addressed identity;
2. decodes the exact nested newline-terminated v2 bytes semantically, with no
   reconstruction, substitution, auto-wrap, or alternate top-level format;
3. uses the v2-approved Git revision to read only fixed path
   `infra/trusted-time/post-enrollment-operator-attestation-authority.json`
   from the exact reviewed Git tree;
4. requires that tree entry to be a regular Git blob with exact mode `100644`
   and binds its Git object identity and canonical bytes, never mutable
   working-tree bytes;
5. strictly decodes the canonical non-identity prime-order-subgroup Ed25519
   authority and verifies every authority/contract/key/public-key/replay-domain
   statement binding;
6. verifies plain Ed25519 over the exact canonical newline-terminated statement
   bytes, not a digest and not Ed25519ph;
7. requires the sole signed decision
   `approve_one_post_enrollment_start_attempt`; and
8. reauthenticates the exact stable image provenance already bound by the
   embedded v2 approval.

The private exact built-in loaded-approval snapshot binds
`operator_authority_git_revision`,
`operator_authority_git_relative_path`, `operator_authority_git_mode`,
`operator_authority_git_blob_object_id`,
`operator_authority_artifact_sha256`, `operator_public_key_sha256`,
`execution_approval_v2_sha256`,
`operator_attestation_statement_sha256`,
`operator_attestation_signature_sha256`,
`operator_attestation_envelope_sha256`, and the exact verification
contract/service/status alongside the semantic approval, stable provenance,
external artifact identity, and exact bytes/inodes. The returned heap receipt
and its fields, descriptors, methods, and fact properties are non-authorizing
views; authority consumers use only the private snapshot's numeric slots.

An absent authority Git object, wrong tree mode or object type, mutable-path
substitution, noncanonical authority, invalid signature, statement/envelope
cross-binding error, semantically invalid v2 bytes, wrong content-addressed
name, or unsigned v2 artifact fails closed. There is no default authority,
fallback key, test key, installed-path `Path.read_*` call, signer, private-key
input, or network lookup.

The host derives the approved launch only from the semantically reconstructed
embedded v2 approval and requires current `HEAD` to equal that exact v2-approved
revision before any Docker, issuer, runtime-input, or reversible preflight. Its
terminal acceptance remains bound to that embedded approval's operation and
approval SHA-256.

### Attempt and admission cutover

Contracts `phase6d-post-enrollment-start-execution-attempt-v3` and
`phase6d-post-enrollment-start-execution-admission-v3` replace v2 on the
execution-facing path. Reservation accepts only the loaded operator-attested
receipt and a fresh image admission. The retained attempt and process-sealed
admission bind the complete v3 identity, including the exact authority Git
object/artifact, public key, statement, envelope, signature-authentication, and
embedded-v2 identities, in addition to the existing stable provenance, fresh
witness, process/thread, clock, and artifact-root bindings.

Reservation and one-shot consumption both reopen and fully revalidate the
operator-attested artifact, reviewed Git authority, exact nested v2 approval,
stable provenance, current fresh image witness, and permanent slot. A
verification-only ADR-0101 result is never accepted as authority by itself;
only this complete semantic, provenance, freshness, replay, and process-sealed
composition can reach the unchanged late choreography continuation.

The fixed slot filename remains
`.post-enrollment-start-execution-attempt-slot`. A complete canonical historical
`phase6d-post-enrollment-start-execution-attempt-v2` slot is classified as
permanently consumed, just like a complete v3 slot.
Unknown-version, malformed, truncated, staging, partial, mismatched, or
otherwise ambiguous slot state is retention-unconfirmed and never retryable.
No migration deletes, rewrites, or upgrades historical slot bytes.

The late chronology remains exact: prepare sequence 1; prepare the exact-empty
reviewed create; reserve the v3 attempt; consume and revalidate the
operator-attested artifact, slot, and fresh witness; store
`mutation_may_have_begun`; then execute only the already-prepared reviewed
create. The cutover does not move reservation earlier and does not weaken any
pre-claim teardown, claim, recovery, controller, sequence-2, or terminal-outcome
rule from ADR 0099.

The canonical v2 byte codec and retention helpers remain only to create and
semantically reconstruct the nested artifact used by the signed envelope.
They are not execution-facing loaders or aliases, cannot feed reservation or
the host, and do not provide an unsigned fallback.

### Reachability and operational state

The execution-admission module is the sole production consumer of the
operator-attestation codec/verifier and reviewed-authority Git-object helper.
The standalone host orchestrator is the sole production consumer of the loaded
operator-attested receipt and its v3 reserve/consume continuation. No Make
target, Compose service, normal launcher, worker, trader, API, controller, or
runtime module invokes the host entry.

This is still code-only. The fixed authority path is intentionally absent, no
real public key or v3 envelope was installed or admitted, and no attempt slot,
Docker topology, release marker, sequence 2, or terminal outcome was created by
this change. No attempt or effect occurred. Absence of the exact reviewed
authority makes every operational v3 load fail before preflight. Public-key
installation alone still grants no execution authority.

Before any real invocation, an operator must complete ADR 0100 installation,
review/commit/merge the identical authority bytes, rebuild exact provenance,
prepare and review the canonical v2 artifact, complete ADR 0102's external
statement/signature/envelope handoff, review every pinned digest, obtain a
fresh image witness through the host preflight, and make one explicit
operational invocation decision. There is deliberately no Make executor.

## Rejected alternatives

- **Keep unsigned v2 as a compatibility path.** That is an authentication
  downgrade and would make the signed decision optional.
- **Read the installed working-tree path.** Mutable bytes do not prove which
  authority was reviewed by the v2-approved revision.
- **Add the absent manifest to unconditional reviewed inputs.** That would
  break current image review before provisioning; the dedicated Git-object
  accessor fails only when v3 execution is actually requested.
- **Verify only at initial load.** Same-UID artifact replacement and stale
  witness state must fail again at reservation and consumption.
- **Use a new attempt filename.** That could bypass a permanently consumed v2
  attempt. Versioned canonical decoding belongs inside the unchanged slot.
- **Treat cryptographic verification as admission.** A valid signature alone
  supplies neither v2 semantics, current source provenance, fresh image
  evidence, durable single use, nor the live choreography capability.
- **Add a Make execution target.** Operational invocation remains an explicit,
  separately reviewed isolated host action.

## Consequences

The code now has one execution-facing format and one supported host composition:
operator-attested v3. Every unsigned-v2 downgrade and mutable-authority route
fails before preflight, while the existing permanent slot preserves exact v2
history and the mutation chronology is unchanged.

This decision does not claim a live start. Until the fixed reviewed authority
exists and the full external review/provenance/invocation sequence is completed,
the v3 executor remains unusable by design. Shutdown, watchdog deployment,
readiness, re-arm, alert delivery, exposure, broker, paper-trading, live-trading,
and Phase 6 exit evidence remain separate later work.
