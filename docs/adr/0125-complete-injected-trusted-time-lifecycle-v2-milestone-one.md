# ADR 0125: Complete injected trusted-time lifecycle-v2 milestone one

- Status: Accepted for a promoted and exact-main-CI-verified, unreachable,
  injected milestone-one implementation at
  `c64cbb2da0e600a3899387d3d58e6a7d8762b00c`; this is implementation-closure
  evidence, not runtime authority
- Date: 2026-08-27
- Completes milestone one of:
  [ADR 0121](0121-trusted-time-graceful-stop-lifecycle-v2-implementation-resolution.md)
- Supersedes the current-status and deferred-work lists in:
  [ADR 0124](0124-trusted-time-lifecycle-v2-milestone-one.md)
- Preserves:
  [ADR 0112](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)

## Context

ADR 0124 recorded the first deliberately partial, unreachable implementation of
ADR 0121 milestone one. It established independent lifecycle-v2 values and
codecs, one injected repository, the separately guarded ADR-0112 v2 handoff,
and simple test-only transport and ordered-effect fakes. It deliberately left
the authenticated authority, transport, terminal evidence, Docker HTTP
evidence, physical-store, complete lifecycle, and recovery surfaces open.

Wave 6 implements those remaining milestone-one contracts without crossing the
activation boundary. The implementation is still assembled only through
private injected and test-only seams. There is no endpoint or signer process,
private-key owner, credential provisioning, production artifact root, real
Docker transport, effecting controller, production caller, deployment wiring,
or enabled stop target.

This decision records implementation completion, not operational readiness.
Milestone two, the Phase 6 exit gate, the paper-trading MVP gate, and every stop,
paper, or live authority remain open.

## Decision

### Complete the canonical authority, identity, channel, and signed-frame family

The independent v2 family now includes exact canonical contracts for the
root-signed transport authority manifest and selection, recovery selection,
boot epoch, process epoch, peer credentials, socket identity, host hello,
supervisor hello, host channel confirmation, channel binding, and complete
request/result/error envelopes.

The injected Ed25519 adapter verifies the offline-root authority and selection
chain, the three-message handshake, direction/role/generation/counter/deadline
bindings, the complete payload, and the root-plus-ordinal-one lifecycle dispatch
prefix. It can also reauthenticate the exact retained signed-wire bytes after a
repository restart. Authentication results are verifier-issued, identity-bound,
one use, and invalid after mutation, wrong-thread use, or fork. The production
module contains no private key, key loader, installed-authority reader, socket
transport, or production caller.

Test-only signing and fake-authentication paths are restricted to exact injected
test roots. They cannot mint an authenticated production-root value, and raw or
constructor-forged envelope/proof objects do not cross the repository or
terminal boundaries.

### Complete clean-stop terminal and Docker HTTP evidence

The terminal family now captures the complete canonical clean-stop result and
error, twenty-field terminal projection, supervisor cleanup commitment, exact
wire-publication receipt, and retained terminal-wire evidence. Exact signed
envelope bytes, payload, signature, publication identity, and semantic result
must agree; a digest-only or structurally decoded value is not authentication.

The Docker family fixes the method-narrowed `/v1.45` plan, full request shape,
bounded HTTP/1.1 response framing, duplicate-aware bounded JSON, typed
container/network/volume projections, daemon and per-connection identities,
six-read admission capture, ordinals `0..17`, complete exchanges and traces,
closed mutation-result semantics, and unchanged two-volume proof. It exposes no
generic request method and no volume-delete method.

The test-only byte-level daemon accepts the exact request bytes in the exact
ordinal order and returns bounded raw HTTP bytes. Disconnect, framing, status,
body, projection, identity-drift, volume-drift, replay, and ambiguous-response
faults burn the fake. It opens no real Docker socket and performs no effect.

### Add a descriptor-safe injected physical store

The physical artifact-store adapter opens only one caller-supplied, already
admitted absolute `trusted-time` directory. It has no default root and creates
no directory. Opaque native descriptor owners enforce no-follow component
opening, exact directory and regular-file device/inode/owner/mode/link identity,
bounded stable inventory, exclusive staging, complete writes, file fsync,
no-replace rename, directory fsync, and reopened stable readback.

Publication failure or identity drift closes the owner and remains ambiguous;
an exact existing final is durably revalidated and never replaced. The fixed
outcome-marker path can finalize only the exact preallocated staging preimage.
Native fork-child invalidation closes inherited descriptors before Python can
reuse them. The adapter still has no production caller, production root,
signer, or effect authority.

### Complete the injected normal lifecycle through confirmed success

The repository and typed lifecycle semantics now cover the exact normal
lineage from ordinal one through authenticated terminal cleanup at ordinal
twenty-two and the fixed confirmed-success outcome at ordinal twenty-three.
Every retained record is reached through a named typed transition; no public or
module-replaceable generic append path can manufacture progress. Each result
retains the exact request, connection, exchange, trace, semantic evidence, and
preceding intent it authenticates.

Ordinal six retains the complete canonical fresh pre-effect ADR-0109 binding
evidence, including its full observation primitives, and ordinal twenty retains
the complete canonical distinct post-teardown binding evidence. Their nested
bytes and semantic digests are revalidated against the exact operation, root,
channel, clean-stop result, issuer, provider, expected head, and observation
interval. Neither a reduced digest projection nor the first observation can
stand in for the terminal binding.

Confirmed success consumes one exact sealed ordinal-twenty-two lineage and the
repository's byte-identical retained prefix. It derives the outcome from that
snapshot, publishes the outcome candidate, proves success-relevant descriptor
and registry disposal, performs the final equality-expired `CLOCK_BOOTTIME`
authorization check, and only then publishes the fixed marker. Any candidate,
disposal, clock, staging, marker, or readback ambiguity is unconfirmed and
cannot produce an alternate outcome. Post-commit lease/registry disposal
remains non-authoritative.

### Complete authenticated classification-only recovery

The recovery family now authenticates the exact root-pinned recovery manifest
and one signed classification envelope, binds it to one known canonical prefix,
and consumes it once into one exact recovery-classification intent. The
repository may then retain only the deterministic `recovery_required` outcome,
or revalidate and finalize the exact already-created outcome/marker preimage.

The recovery seam is generation-, root-, transcript-, nonce-, PID-, and
Thread-bound. Replay, mutation, object construction bypass, wrong-root use,
wrong-thread use, and fork reject. It has no recovery key loader or signer
owner, cannot dispatch transport, cannot call Docker, cannot retry or continue
an effect, and cannot create a new confirmed-success candidate.

### Preserve the non-authority boundary

All Wave 6 composition remains unreachable from ordinary runtime paths. There
is no real Unix-seqpacket endpoint, signer process, private-key custody owner,
encrypted-credential provisioning, admitted tmpfs/key/socket resource, default
or production artifact root, real Docker Unix transport, production cleanup
observer, controller, CLI, Make/Compose wiring, deployment/bootstrap caller, or
stop effect.

`make trusted-time-stop` remains the exact no-prerequisite hard close. It prints
`trusted-time-stop is approval-blocked: no effecting approved shutdown operator is implemented`
to standard error and exits 2 without invoking Python or Docker. The trader
remains `not_ready`, and no paper or live order authority is added.

## Implementation evidence and closure status

Focused tests cover canonical round trips and rejection, signature tampering,
authority/generation/root mismatch, retained-wire restart authentication,
packet/payload/JSON size-depth-node boundaries, the exact Docker request and
response matrix, byte-level daemon faults, physical publication faults,
wrong-thread and fork invalidation, complete ordinal sequencing, nested evidence
substitution, distinct ADR-0109 observations, confirmed-success marker faults,
and authenticated recovery replay and ambiguity.

Architecture policy isolates every new authority-bearing module and private
seam, reserves removed bypass names, constrains reviewed cross-imports, and pins
the final production and native source bytes. The reconciled architecture/
source seals and independent read-only review of the stabilized source and
configuration tree pass. The full local
backend regression reports 12,301 passed and 1,097 skipped; frontend lint,
typecheck, 67 Vitest tests, 33 bundle-policy tests, and the production build
pass; and native Python 3.12/3.13 packaging parity reports 142 passed with 36
expected skips. Wave 6 is promoted to local and remote `main` at exact revision
`c64cbb2da0e600a3899387d3d58e6a7d8762b00c`. Exact-main
[CI run #136](https://github.com/km8trix/AutoQuantTrader/actions/runs/33171993916)
passed all 11 jobs: architecture, four backend/PostgreSQL shards, four native
OS/Python packaging jobs, browser quality/tests/build, and container/paper
admission including the production fail-closed and trusted-time evidence-image
gates. These facts close Wave 6 implementation, repository promotion, and
remote-CI verification only; they add no deployment, stop authority,
operational authority, or milestone-two completion.

## Supersession and remaining roadmap

ADR 0124 remains the historical record of the Wave 5 partial core. This ADR
supersedes ADR 0124 only for the current milestone-one status and its list of
deferred milestone-one implementation work. ADR 0121 remains the normative
protocol and rollout decision.

ADR 0121 milestone two is next. It must add native endpoint and signer owners,
the native fork guard and fixed launch profiles, encrypted credential
provisioning and zeroization, admitted tmpfs mounts and key/socket resources,
and the associated native isolation while still providing no real-root path and
leaving `trusted-time-stop` unchanged. Milestones three and four, production
composition, deployment, operational drills, and every authority gate remain
later work.

## Consequences

Reviewers can now evaluate one complete injected milestone-one protocol rather
than extrapolating from partial schemas or digest projections. The implementation
can prove exact evidence and ambiguity behavior without possessing the resources
needed to stop anything.

The boundary remains intentionally unusable for operations. A future native
owner or production composition cannot infer permission from this ADR; it must
satisfy ADR 0121's later milestones and activation evidence independently.

## Rejected alternatives

- **Treat complete injected contracts as an enabled shutdown path.** Contract
  completion supplies no endpoint, key custody, root, caller, effect, or
  authority.
- **Defer full ADR-0109 evidence behind outer digests.** Ordinals six and twenty
  retain the complete canonical binding and observation primitives so a later
  reader does not need an unavailable process-local seal to authenticate them.
- **Accept structural wire decoding after restart.** Retained bytes must pass
  the exact selected Ed25519 authority and terminal-payload verification path.
- **Use a convenient path-based file adapter or in-process Docker stub as
  physical evidence.** Descriptor-owned publication and the byte-level fake
  daemon exercise the actual ambiguity and framing boundaries without reaching
  a production root or Docker socket.
- **Advance directly to real owners or a production caller.** That belongs to
  milestone two or later and would violate the reviewed zero-caller wave.
