# ADR 0101: Inert post-enrollment operator-attestation verification

- Status: Accepted (pure statement/envelope codec and public-key verifier
  implemented and composed only by ADR 0103; no authority installed, signer,
  or execution)
- Date: 2026-08-14
- Extends:
  [ADR 0100](0100-post-enrollment-operator-public-key-provisioning.md) and
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)

## Context

ADR 0100 freezes one dedicated Ed25519 public-authority manifest and an offline
review-before-install workflow. The fixed authority file is still absent, and
the private key remains outside the repository and every AutoQuantTrader
process. ADR 0103 now adds the sole production loader, but it can authenticate
only the exact reviewed Git object and fails while that object is absent.
Installing public material would identify a verification key, but would not by
itself authenticate an operator decision.

ADR 0099's stable v2 execution-approval artifact is canonical and content-
addressed but is not an authenticated operator signature. ADR 0103 rejects
downgrade to that unsigned form while preserving the distinction between
stable human approval and the fresh image witness plus explicit operational
decision required for each attempt.

Before any integration is designed, the byte-level signature contract needs a
small dependency-neutral codec and verifier. It must be possible to test that
contract without provisioning a real key, reading a mutable authority path, or
making the effecting host executor reachable. Signature validity alone cannot
prove freshness, single use, semantic validity of the wrapped v2 artifact, or
permission to reserve an attempt.

## Decision

Implement a pure, inert operator-attestation statement and v3 envelope codec.
The verifier receives the exact authority object explicitly from its caller;
it has no fixed-path loader, default authority, test fallback, filesystem,
environment, standard-input, network, database, clock, randomness, Docker,
Compose, controller, host-orchestrator, attempt, admission, or runtime surface.

Pure domain classes `TrustedTimePostEnrollmentOperatorAttestationStatement` and
`TrustedTimePostEnrollmentOperatorAttestationEnvelope` own only canonical byte
construction and decoding. Cryptographic verification is isolated in adapter
`Ed25519PostEnrollmentOperatorAttestationVerifier`, constructed only through
`from_authority(authority)`. Its sole operation `verify(envelope)` returns
`TrustedTimePostEnrollmentOperatorAttestationVerification` or raises the one
sanitized
`TrustedTimePostEnrollmentOperatorAttestationVerificationError`. Neither layer
discovers authority or owns a caller.

Authority construction and decoding first require the exact canonical
Edwards25519 encoding of a non-identity point in the prime-order subgroup. The
adapter independently repeats that public-point validation before constructing
the cryptographic public key and again before signature verification. Identity
or other torsion points, mixed-subgroup points, noncanonical encodings, and
off-curve values fail closed; a permissive backend's acceptance of 32 bytes is
not treated as proof of a usable signing authority.

The signed statement binds all of the following:

- the fixed algorithm `Ed25519`;
- the exact canonical authority-manifest SHA-256 and authority contract
  `phase6d-post-enrollment-operator-attestation-authority-v1`;
- fixed key ID `aqt-post-enrollment-start-operator-ed25519-v1` and the exact
  raw-public-key SHA-256;
- replay domain
  `github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-start/operator-attestation/v1`;
- statement contract
  `phase6d-post-enrollment-start-operator-attestation-statement-v1`, service
  `trusted-time-post-enrollment-start-operator-attestation`, and status
  `exact_one_attempt_execution_approval_statement`;
- the sole decision `approve_one_post_enrollment_start_attempt`;
- exact v2 contract
  `phase6d-post-enrollment-start-execution-approval-v2`; and
- the lowercase SHA-256 of the exact canonical newline-terminated v2 artifact
  bytes.

The statement contains exactly these 12 fields and no extensions:
`algorithm`, `authority_artifact_sha256`, `authority_contract_version`,
`contract_version`, `decision`, `execution_approval_contract_version`,
`execution_approval_v2_sha256`, `key_id`, `public_key_sha256`, `replay_domain`,
`service`, and `status`.

The signature is plain Ed25519 over the exact canonical newline-terminated
statement bytes. It is not a signature over the statement SHA-256, does not
apply an implicit prehash, and is not Ed25519ph. The statement SHA-256 exists
only as an envelope binding and evidence identity.

At this codec layer, the inert envelope contract is
`phase6d-post-enrollment-start-execution-approval-v3`. It carries canonical
standard Base64 of the exact v2 artifact bytes, their SHA-256, the exact nested
statement and its SHA-256, fixed algorithm `Ed25519`, canonical standard Base64
of exactly 64 signature bytes, service
`trusted-time-post-enrollment-start-execution-approval`, and status
`operator_attested_execution_approval_envelope`. Its exact nine fields are
`contract_version`, `execution_approval_v2_base64`,
`execution_approval_v2_sha256`, `operator_attestation_statement`,
`operator_attestation_statement_sha256`, `service`, `signature_algorithm`,
`signature_base64`, and `status`. Base64 keeps the v2 bytes byte-for-byte intact
without duplicating or weakening the large v2 semantic decoder inside this
narrow domain module.

Decoding rejects duplicate, missing, extra, mistyped, noncanonical, oversized,
or structurally ambiguous input. It rejects noncanonical JSON or Base64, every
fixed algorithm, authority-contract, key-ID, replay-domain, statement, v2-
contract, cross-digest, or signature-length mutation, including any v2-byte
change not reflected through every nested digest. The verifier separately
rejects an authority-artifact or public-key identity mismatch and any signature
or signed-statement mutation that does not authenticate under the explicit
authority. An unsigned v2 artifact is not a v3 envelope, and no function
auto-wraps or upgrades it.

Successful public-key verification returns only inert status
`operator_signature_authenticated_unqualified` under contract
`phase6d-post-enrollment-operator-attestation-verification-v1` and service
`trusted-time-post-enrollment-operator-attestation-verification`. The result
authenticates the signature over the exact statement bytes under the explicit
authority and records the canonical envelope identity after cross-validating
its byte/digest relationships. It binds only `authority_artifact_sha256`,
`public_key_sha256`, `execution_approval_v2_sha256`,
`operator_attestation_statement_sha256`, and
`operator_attestation_envelope_sha256`, plus `verification_only=true` and
explicitly false operational-authority fields. It deliberately does not
semantically decode the v2 artifact and does not establish that its proposed revision, images,
provenance, or enrollment bindings are valid. It grants no execution,
attempt-reservation, admission, controller, runtime-start, readiness, exposure,
broker, paper-trading, or live-trading authority.

The exact explicitly false field set is `active_controller_authorized`,
`alert_delivery_authorized`, `arming_authorized`, `authority_granted`,
`automatic_rearm_authorized`, `automatic_resume_authorized`,
`broker_action_authorized`, `claim_retention_authorized`,
`controller_execution_authorized`, `database_secret_disclosed`,
`execution_admission_authorized`, `execution_attempt_reservation_authorized`,
`exposure_authorized`, `live_trading_authorized`, `new_exposure_authorized`,
`operational_control_authorized`, `outcome_retention_authorized`,
`paper_trading_authorized`, `persistent_start_authorized`,
`readiness_authorized`, `rearm_authorized`, `release_authorized`,
`retry_authorized`, `runtime_start_authorized`, `sequence_2_authorized`,
`shutdown_authorized`, `source_start_authorized`,
`success_outcome_retention_authorized`, `supervisor_start_authorized`, and
`topology_mutation_authorized`.

This ADR's v3 codec/verifier itself adds no Make target, CLI, authoring command,
authority loader, signer, execution-admission version change, host-orchestrator
import, Compose/runtime wiring, or external key-import workflow. ADR 0102 adds
only an isolated offline statement-candidate and detached-signature
verification workflow. ADR 0103 is now the codec/verifier's sole
production consumer, but only inside a complete v3 semantic/provenance/replay
gate. The fixed authority source path remains absent, so there is still no
operational verification or use.

## Atomic admission integration in ADR 0103

ADR 0102 prepares exact external candidates under this byte contract, but that
public-only workflow is not admission and does not satisfy any item below.

ADR 0103 integrates this contract atomically and:

- authenticate the authority from the exact reviewed Git object associated
  with the v2-approved revision rather than trusting mutable working-tree bytes;
- require v3 exclusively, with no unsigned-v2 fallback, auto-wrap, or downgrade;
- semantically decode and revalidate the exact wrapped v2 bytes;
- bind authority, statement, envelope, and v2-artifact digests into v3
  attempt and admission contracts;
- preserve the existing fixed attempt-slot filename and treat every complete
  historical v2 slot as permanently consumed;
- reload and reverify the authority, envelope, v2 approval, slot, and fresh
  image witness at both reservation and consumption;
- fail before attempt reservation and before reversible or effecting preflight
  when authority or attestation evidence is absent or ambiguous; and
- preserve pre-slot retry semantics and the separate explicit operational
  invocation decision.

Freshness, durable replay/single-use enforcement, attempt-slot integration,
admission, host invocation, and controller execution remain outside this ADR;
ADR 0103 supplies that separate composition. The decision string still does not
make a bare verified envelope single-use, and no effecting path may consume the
verification result in isolation. Operational use remains impossible until the
real authority is provisioned and reviewed through ADR 0100 and the external
artifact handoff is completed through ADR 0102.

## Rejected alternatives

- **Sign the v2 digest instead of the statement.** That would leave fixed
  decision, authority, replay-domain, and contract bindings outside the signed
  message.
- **Use Ed25519ph or an undocumented prehash.** This would create a different
  signature protocol and make external authoring ambiguous.
- **Rely on public-key length or backend parsing alone.** Some Ed25519 backends
  accept identity or other non-prime-subgroup encodings; the identity point can
  make an identity-point/zero-scalar signature verify without a private key.
- **Decode and trust mutable authority-file bytes in the pure verifier.** The
  later integration must authenticate the exact reviewed Git object; a working-
  tree path is not source provenance.
- **Reuse unsigned v2 when v3 is absent.** This is a downgrade and must fail
  closed.
- **Treat signature authentication as execution authority.** Verification says
  which key signed exact bytes; it proves neither semantic approval validity,
  freshness, single use, nor permission to cause an effect.
- **Add a signer or private key for tests or convenience.** Fixed public-only
  vectors can test verification without putting signing authority in the
  repository or runtime.

## Consequences

The repository gains an exact, testable byte protocol for an external operator
signature without granting authority at this layer. The v3 envelope preserves
exact v2 bytes and fails closed on every identity or signature mutation, but
its verified result remains explicitly unqualified outside ADR 0103's complete
admission composition.

The fixed authority is still absent, no real attestation can be used, and ADR
0103 removes unsigned v2 from the execution-facing path rather than authorizing
it. ADR 0102 separately supplies only an offline external statement/envelope
candidate workflow. Before any real attempt, ADR 0100 provisioning, that
external artifact handoff, exact merged provenance, a fresh image witness, and
an explicit operational execution decision all remain required.
