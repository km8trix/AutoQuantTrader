# ADR 0100: Post-enrollment operator public-key provisioning

- Status: Accepted (public-material preparation and fixed-path installation
  implemented; no authority installed and no effecting execution authorized)
- Date: 2026-08-14
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)

## Context

ADR 0099 separates a stable, content-addressed execution approval from the
fresh image witness and explicit operational decision required for each
attempt. The current approval artifact remains an externally supplied input,
but the repository has not yet frozen a distinct public trust root with which a
later contract can authenticate an operator attestation. Reusing the trusted-
head checkpoint key would collapse two authorities: the service identity that
signs sparse time-head records and the human/operator identity that approves
one exact post-enrollment controller tuple.

The private half of an operator key must remain in an independently controlled
offline or hardware-backed signing system. A repository command that generates,
loads, receives, or signs with that private key would turn a public trust-root
change into a secret-handling and effecting surface. Passing key material
through an environment variable or standard input would also make source,
shell, process, and audit boundaries harder to review.

The repository therefore needs a narrow provisioning path for public material
only. It must make the candidate bytes reviewable before they can occupy the
fixed source path, and installation must be bound to both the exact candidate
bytes and the exact raw public key. Provisioning itself must not start the
runtime, reserve an attempt, admit an execution, access Docker or a database,
or make a network request.

## Decision

Freeze one dedicated Ed25519 verification authority for future
post-enrollment operator attestations. Its private key is generated and held
outside this repository and outside every AutoQuantTrader process, container,
environment file, database, artifact directory, and image. The external key
system exports only the exact raw 32-byte Ed25519 public key to an absolute
operator-owned file. The key must not be the trusted-time head-anchor signing
key or any broker, deployment, or user-session key.

The public authority manifest has exactly these eight fields and no extensions:

- `algorithm`: `Ed25519`;
- `contract_version`:
  `phase6d-post-enrollment-operator-attestation-authority-v1`;
- `key_id`: `aqt-post-enrollment-start-operator-ed25519-v1`;
- `public_key_base64`: canonical standard Base64 for exactly 32 raw bytes;
- `public_key_sha256`: lowercase SHA-256 of those exact raw bytes;
- `replay_domain`:
  `github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-start/operator-attestation/v1`;
- `service`: `trusted-time-post-enrollment-operator-attestation-authority`; and
- `status`: `public_operator_authority_material`.

The canonical representation is compact, newline-terminated JSON. It rejects
duplicate or unknown fields, noncanonical JSON or Base64, a key of any other
length, digest mismatch, and drift in any frozen string. The manifest is public
verification material only. Its presence does not authenticate an approval,
authorize controller execution, reserve an attempt, establish freshness, or
grant runtime, readiness, exposure, broker, paper-trading, or live-trading
authority.

Provisioning has two deliberately separate offline phases.

### Phase 1: prepare a candidate for review

From a repository checkout, supply the absolute external public-key file and a
distinct absolute candidate directory outside the repository. Each parent is a
pre-existing current-user-owned directory with exact mode `0700`; the raw key
is a single-link regular file with mode `0400` or `0600`:

```console
make trusted-time-prepare-post-enrollment-operator-authority \
  TRUSTED_TIME_OPERATOR_PUBLIC_KEY_FILE=/absolute/operator/public-key.raw \
  TRUSTED_TIME_OPERATOR_CANDIDATE_DIRECTORY=/absolute/operator/authority-candidates
```

The isolated, offline command reads exactly 32 bytes from the public-key file,
builds and decodes the canonical manifest, and publishes one owner-only,
content-addressed mode-`0600` candidate. It does not install the candidate. Its
stdout is a canonical public receipt with status
`public_operator_authority_candidate_prepared`, the candidate filename, both
digests, fixed key/replay identities, `verification_only=true`, and every
authority field false. Review the reported authority-artifact SHA-256,
raw-public-key SHA-256, fixed key ID, replay domain, and exact candidate bytes.
Compare the public-key digest with an independent display or export from the
external key system. Do not infer private-key possession from this public-
material check.

Do not copy, export, paste, or point this command at the private key. The
provisioner has no private-key flag, generator, decoder, signer, environment-
file input, standard-input mode, or network-backed key interface.

### Phase 2: install the exact reviewed bytes

Only after the candidate and both digests have been reviewed, invoke the
separate installation phase:

```console
make trusted-time-install-post-enrollment-operator-authority \
  TRUSTED_TIME_OPERATOR_CANDIDATE_ARTIFACT=/absolute/operator/authority-candidates/trusted-time-post-enrollment-operator-attestation-authority-<sha256>.json \
  TRUSTED_TIME_OPERATOR_APPROVED_AUTHORITY_SHA256=<reviewed-authority-sha256> \
  TRUSTED_TIME_OPERATOR_APPROVED_PUBLIC_KEY_SHA256=<reviewed-public-key-sha256>
```

Installation reopens and revalidates the candidate, requires both supplied
digests to match, and installs identical bytes at the one fixed path:

`infra/trusted-time/post-enrollment-operator-attestation-authority.json`

It does not regenerate, normalize, or substitute the manifest during install.
The installer uses owner-held no-follow descriptors, `O_EXCL`, file and
directory fsync, exact readback, and fixed mode `0644`. An existing different
destination fails closed; an existing file is accepted only when its bytes and
mode are already exact and can be re-fsynced and revalidated. The successful
public receipt status is
`public_operator_authority_installed_for_source_review`; it still records
`verification_only=true` and every authority field false. The fixed path is
intentionally absent from the repository until an operator completes this
phase. There is no placeholder or default key.

After installation, review the exact source diff and manifest digests, then
commit, obtain normal code review, merge, and rebuild provenance from the exact
merged revision. The fixed authority path is explicitly excluded from Docker
build context, and no Compose, supervisor, worker, trader, ordinary launcher,
controller, execution-admission, or image-verifier surface consumes it in this
slice. A later change must separately define and review signed-attestation
bytes, verification, replay handling, and their relationship to the existing
execution-approval contract before any controller path can use this trust root.

Key replacement is not an in-place edit. A rotation requires a new reviewed
contract/key identity, explicit migration and overlap or cutover rules, and a
separate ADR. The v1 installer cannot be used as a mutable key registry.

## Rejected alternatives

- **Generate or store the private key in this repository.** This would put
  signing authority inside the system it is meant to approve.
- **Reuse the trusted-head checkpoint key.** This would merge service-record
  integrity with operator execution approval and destroy independent rotation
  and compromise boundaries.
- **Install directly from a public-key file.** This would remove review of the
  exact canonical manifest and its content address before the source change.
- **Accept key material through environment variables or standard input.** This
  would add unnecessary process and shell secret-adjacent surfaces and weaken
  reproducible review.
- **Bundle the authority into runtime images now.** No signed operator-
  attestation verifier is admitted, so doing so would create an unused and
  easily misread runtime authority surface.
- **Treat public-key installation as execution approval.** A trust root says
  which future signatures may be checked; it is not itself a signed decision
  over a controller tuple.

## Consequences

The repository gains a reproducible, review-before-install path for one exact
public Ed25519 trust root without gaining a signer. Candidate and installed
bytes are content-addressed and independently bound to the raw public key. The
fixed absence of a default manifest keeps later verification fail-closed until
the operator explicitly installs reviewed material.

This change performs local public-file preparation or installation only. It has
no runtime, controller, admission, attempt, Docker, database, provider, network,
or trading effect. It neither changes the existing v2 execution-approval,
attempt, and admission contracts nor claims a successor execution-admission
contract. A future signed-attestation slice must remain separately reviewable
and must preserve the attempt-local witness and explicit operational decision.
