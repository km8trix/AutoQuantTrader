# ADR 0102: Offline post-enrollment operator-attestation artifacts

- Status: Accepted (code-only offline candidate preparation and public-signature
  verification implemented; no signer, admission, runtime, or execution)
- Date: 2026-08-14
- Extends:
  [ADR 0101](0101-inert-post-enrollment-operator-attestation-verification.md)
  and
  [ADR 0100](0100-post-enrollment-operator-public-key-provisioning.md)

## Context

ADR 0101 freezes the exact canonical statement, v3 envelope, and public-key
verification contracts for an external operator attestation. Its pure
codec/verifier deliberately has no filesystem surface, authority discovery,
signer, CLI, or production caller. ADR 0100 separately provides review-before-
install handling for public authority material while keeping the private key in
an independently controlled offline or hardware-backed signing system.

An operator still needs a deterministic, reviewable way to prepare the exact
bytes that external equipment will sign and then to combine the returned
detached signature with the same authority and v2 approval. That workflow must
not read the installed fixed authority path or blur public verification with
private signing. It also must not make a cryptographically valid envelope look
semantically approved, fresh, single-use, admitted, or executable.

## Decision

Add one code-only offline artifact workflow at
`scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py`. It has
exactly two public operations:

- `prepare_post_enrollment_operator_attestation_statement_candidate`; and
- `verify_and_retain_post_enrollment_operator_attestation_envelope_candidate`.

The corresponding CLI subcommands are `prepare-statement` and
`verify-signature`. Two Make targets expose only those non-effecting operations:

- `trusted-time-prepare-post-enrollment-operator-attestation-statement`; and
- `trusted-time-verify-post-enrollment-operator-attestation-envelope`.

Every input and output path is explicit and absolute. Every input is an exact
single-link current-user-owned regular file with mode `0400` or `0600` beneath
an external current-user-owned directory with exact mode `0700`. Candidate
output directories are separately supplied, pre-existing external directories
with the same exact ownership and mode. Outputs are created as owner-only mode
`0600` files with exclusive creation, durable publication, and exact readback.
The workflow accepts no repository default, fixed installed-authority path,
environment-file input, environment-variable input, or standard input.

### Prepare the statement candidate

`prepare-statement` accepts:

- an explicit external ADR-0100 authority candidate;
- an explicit content-addressed canonical v2 execution-approval artifact;
- an explicit external statement-candidate directory; and
- the reviewed authority-artifact, public-key, and exact-v2-artifact SHA-256
  values.

The authority filename and bytes must retain their ADR-0100 content-addressed
identity. The v2 filename must bind the SHA-256 of its exact canonical newline-
terminated bytes. This workflow validates only the v2 artifact's canonical
top-level contract/service/status identity and exact byte/digest binding. Its
receipt records `canonical_top_level_identity_only_semantics_unqualified`; it
does not run the large v2 semantic decoder or establish that the proposed
revision, images, provenance, enrollment evidence, or execution tuple is valid.

The operation reconstructs and cross-checks the exact ADR-0101 statement and
retains it only at content-addressed filename
`trusted-time-post-enrollment-operator-attestation-statement-<statement-sha256>.json`.
The candidate bytes are the exact canonical newline-terminated bytes to be
signed with plain Ed25519. They are not a digest to sign and do not select
Ed25519ph or any implicit prehash.

The successful public receipt uses contract
`phase6d-post-enrollment-operator-attestation-artifact-receipt-v1`, service
`trusted-time-post-enrollment-operator-attestation-artifacts`, and status
`operator_attestation_statement_candidate_prepared_unqualified`. It reports
`operator_signature_authentication=not_authenticated`, identifies only the
exact public artifacts and reviewed digests, and keeps every operational
authority unqualified or false.

### Verify and retain the envelope candidate

The private key never enters this workflow. An independently controlled external
system signs the exact retained statement bytes and exports only a detached raw
64-byte Ed25519 signature to another external owner-only file.

`verify-signature` reopens the explicit authority candidate, v2 artifact, exact
content-addressed statement candidate, and raw detached-signature file. It also
requires the reviewed authority, public-key, v2-artifact, statement, and raw-
signature SHA-256 values and a separate explicit envelope-candidate directory.
It rejects any name, byte, digest, authority identity, statement relationship,
signature length, or signature authentication mismatch before publication.

Only after rebuilding the exact v3 envelope, decoding it, and verifying its
signature through the ADR-0101 public verifier does the workflow retain exact
canonical bytes at content-addressed filename
`trusted-time-post-enrollment-start-execution-approval-v3-<envelope-sha256>.json`.
The successful receipt uses the same receipt contract and service with status
`operator_attestation_envelope_verified_unqualified` and
`operator_signature_authentication=authenticated_unqualified`. Verification
proves only that the exact authority authenticated the exact statement and that
the envelope's byte/digest relationships are exact. The retained envelope
remains an external candidate, not an installed source artifact or execution
input.

Both sealed digest-only receipts set `structural_receipt_only=true`,
`verification_only=true`, `execution_approval_v2_semantically_qualified=false`,
`freshness_qualified=false`, `single_use_qualified=false`,
`installed_authority_used=false`, and
`later_atomic_cutover_revalidation_required=true`. Every inherited operational-
authority field is false. The envelope receipt adds only the detached-signature
and envelope SHA-256 identities to the statement receipt's public fields.

Both operations are isolated, offline, and public-material-only. The module has
no Ed25519 private-key construction, generator, reader, decoder, signer, signing
operation, key-provider integration, environment or standard-input channel,
network, database, Docker, Compose, subprocess, clock, randomness, controller,
attempt, admission, host-orchestrator, runtime, or trading surface. No
production caller invokes either public workflow operation, the file is excluded
from Docker build context, and neither Make target installs authority or invokes
any effecting path.

## Atomic admission cutover in ADR 0103

This ADR satisfies only the external authoring-candidate prerequisite named by
ADR 0101. It does not itself implement admission. ADR 0103 separately lands the
atomic integration: authenticate the authority from the exact reviewed Git
object associated with the v2-approved revision, require v3 exclusively,
semantically revalidate the exact wrapped v2 bytes, bind every authority/
statement/envelope/v2 identity into the attempt and admission contracts,
preserve all consumed attempt history, and reload/reverify all evidence at
reservation and consumption.

Freshness, durable replay and single-use enforcement, attempt-slot integration,
admission, host invocation, controller execution, and the explicit operational
decision remain outside this ADR. ADR 0103 provides those code-only admission
bindings and accepts the candidate only through its explicit external path;
there is no repository-default artifact and no unsigned-v2 executor.

## Rejected alternatives

- **Add a repository signer or private-key input.** That would put the approval
  authority inside the system it must independently authorize.
- **Accept signature bytes through an argument, environment variable, or
  standard input.** An explicit owner-only file and reviewed digest preserve a
  bounded, inspectable handoff.
- **Read the installed authority path.** Offline authoring uses the explicit
  reviewed candidate; ADR 0103 separately authenticates the exact reviewed Git
  object rather than mutable working-tree bytes.
- **Treat top-level v2 identity as semantic validation.** Full v2 semantics and
  their integration with v3 belong to ADR 0103's atomic admission cutover.
- **Publish an envelope before public verification.** Candidate retention occurs
  only after all exact identities, digests, canonical bytes, and the detached
  signature authenticate.
- **Let the workflow reserve an attempt or call the executor.** Artifact
  construction and effecting admission are deliberately separate authorities.

## Consequences

An operator can now review the exact message before signing and can retain one
content-addressed, publicly verified v3 candidate after an external signature
handoff. The workflow is reproducible and fail-closed without importing private
signing authority into AutoQuantTrader.

No authority is installed by this change and no v3 candidate has operational
meaning merely because the offline verifier retained it. ADR 0103 accepts only
the complete candidate through its separate code-only gate. Before any real
attempt, ADR-0100 authority installation and source review, exact merged
provenance, full v2 semantic validation, freshness and single-use enforcement,
a fresh image witness, and an explicit operational execution decision all
remain required.
