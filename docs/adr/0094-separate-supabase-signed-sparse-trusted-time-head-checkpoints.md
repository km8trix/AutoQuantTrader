# ADR 0094: Separate-Supabase signed sparse trusted-time head checkpoints

- Status: Accepted
- Date: 2026-08-01
- Extends: [ADR 0090](0090-durable-trusted-time-persistence-and-one-shot-supervision.md), [ADR 0092](0092-evidence-only-local-chrony-nts-trusted-time-supervision.md), and [ADR 0093](0093-system76-virginia-nts-authority-rotation.md)

## Context

ADR 0090 made the local trusted-time journal tamper-evident but explicitly did
not authenticate its terminal head outside the runtime database. ADRs 0092 and
0093 then selected, supervised, and qualified one local Chrony NTS topology,
but retained that same trust limitation. A rollback of only the runtime
database therefore has no separately stored signed checkpoint against which it
can be compared.

External evidence must not delay the fixed 20-second local probe grid, hold a
database transaction across provider I/O, automatically enroll an existing
history, or turn a healthy or externally stored head into trading authority.
It also needs bounded steady-state work even as the retained local and remote
histories grow.

A second Supabase project is operationally convenient, but it is not an
independent storage provider or an independent administrative trust domain.
Supabase Storage is not WORM storage. Project administrators and privileged
provider roles can bypass the application writer's row-level policies, remove
objects, or make the project unavailable. If the same administrator rolls back
both the runtime database and the anchor project to one older mutually
consistent signed prefix, this design has no third-party observation that can
prove the omitted suffix existed. Those limitations must remain visible.

## Decision

Implement provider-neutral contract
`phase6d-provider-neutral-external-trusted-head-anchor-v1`, durable contract
`phase6d-durable-trusted-time-head-anchor-persistence-v1`, single-flight worker
contract `phase6d-single-flight-trusted-head-anchor-worker-v1`, and the bounded
Supabase adapter
`phase6d-separate-supabase-storage-anchor-adapter-v1`.

The normative implementation is split across the
[provider-neutral contract](../../packages/application/trusted_time_head_anchor.py),
[pure worker](../../packages/application/trusted_time_head_anchor_worker.py),
[durable repository](../../packages/persistence/trusted_time_head_anchor.py),
[Supabase Storage adapter](../../packages/adapters/trusted_time/supabase_storage_anchor.py),
and repository-backed
[runtime attempt](../../apps/trusted_time_supervisor/head_anchor_attempt.py).
Strict deployment admission is in
[`head_anchor_config.py`](../../apps/trusted_time_supervisor/head_anchor_config.py),
while the separate-project policy renderer is
[`provision_trusted_time_anchor_project.py`](../../scripts/provision_trusted_time_anchor_project.py).
Offline credential/authority creation is implemented by
[`generate_trusted_time_anchor_artifacts.py`](../../scripts/generate_trusted_time_anchor_artifacts.py),
and the credential-safe Storage behavior operator is
[`prove_trusted_time_anchor_storage.py`](../../scripts/prove_trusted_time_anchor_storage.py).

The admitted deployment contract requires a Supabase project distinct from
both the runtime and test database projects and the exact private Storage bucket
`aqt-trusted-time-anchors-v1`. A least-privilege Supabase Auth writer may list,
read, and insert only canonical JSON objects in its admitted deployment/host
namespace. Normal writer update, overwrite, and delete operations are denied.
The upload API also sets no-overwrite semantics. These controls constrain the
runtime writer; they do not convert Supabase Storage into WORM storage or bind a
Supabase administrator.

The policy renderer admits the entire `storage.objects` policy catalog, not
only names carrying the Phase 6D prefix. Preflight accepts a completely absent
set or the complete exact expected set; postflight requires exact equality to
the expected `aqt_tt_anchor_v1_*` policies. Any unrelated, missing, or changed
policy is drift.

The offline artifact generator exclusively creates one raw 32-byte Ed25519
private key, one exact runtime Auth secret, and one nonsecret authority at
owner-only paths outside the repository. It revalidates the runtime contracts,
emits no secret content, fixes `allow_enrollment=false`, and records enrollment
`UNRUN`.

The behavioral proof requires retained owner-only evidence for a real separate
private control bucket in the anchor project. It authenticates the exact Auth
writer, retains one synthetic canonical object under a proof-only deployment/
host prefix outside the runtime's exact prefix, proves exact list/read/insert
behavior plus strict cross-namespace, cross-bucket, mutation, anonymous, and
public denials, and performs no cleanup. The proof does not enroll history.

Each canonical checkpoint is signed with Ed25519. The raw 32-byte private key
is generated and retained outside Supabase and is supplied to the local
supervisor only through an owner-controlled secret file. The nonsecret
authority binds the exact public key and digest, key ID, source authority,
host, runtime database project, separate anchor project, Auth principal,
bucket, and deployment identity. The anchor project never receives the private
signing key.

The normal checkpoint schedule is an absolute 300-second monotonic grid. An
anchor is stale at 360 seconds or greater, including equality. Epoch rotation,
hard failure, health transition, recovery transition, clean stop, and explicit
on-demand work may request a checkpoint without moving the absolute periodic
grid. One single-flight background thread performs signing and remote I/O so
the 20-second local probe loop does not wait for Supabase. Startup first
authenticates the local SQL tips synchronously after the fresh epoch is
registered; the background thread then performs the remote audit.

Startup and explicit on-demand reconciliation authenticate the complete local
journal, durable intent/receipt history, and remote checkpoint prefix. Local
and durable rows are consumed in bounded pages inside one repeatable-read SQL
snapshot. Remote object names and signed records are likewise listed,
downloaded, and authenticated page by page without retaining the full prefix;
a second listing/hash pass rejects namespace drift during the audit.
The completed audit seals a constant-size proof/tip and releases provisional
pages. Memory and retained state are bounded, but full-audit time and provider
requests remain linear in retained history; this decision sets no startup-time
SLO at the maximum horizon.

After that full audit, the compact authenticated tip supports constant-retained-
proof incremental work: steady-state reconciliation authenticates the exact
retained terminal and the exact next remote sequence, plus any newly appended
local suffix. It does **not** scan the remote or local middle history on every
periodic checkpoint. Consequently, an arbitrary middle-row deletion is
detected by the complete startup/on-demand audit, not necessarily by an already
running incremental terminal-plus-next check.

Publishing one new checkpoint follows this durable order:

1. authenticate the local head and prepare the exact signed candidate;
2. commit an immutable local intent before any upload;
3. upload the exact canonical object with no-overwrite semantics;
4. complete provider reconciliation with an exact authenticated readback;
5. independently perform a second provider `GET` and seal its identity and
   exact bytes in application-issued, single-use evidence; and
6. commit the second-readback-bound local receipt.

Persistence accepts only that application-sealed provider-`GET` evidence. A
caller cannot construct the evidence or substitute candidate bytes retained
locally after signing.

A restart or an ambiguous provider result must recover the single durable
pending intent before preparing a successor. A typed, authenticated local-head
compare-and-swap advance is a benign bounded retry because the local 20-second
probe may win while anchoring runs. Only that exact condition and a positively
classified provider-unavailable result are transient. Signature, fork,
rollback, configuration, identity, persistence, malformed-provider, and
unclassified failures are fatal.

Enrollment remains default-deny. The first remote object must have sequence 1
and reason `enrollment`, and requires a full audit plus an explicit runtime
enrollment flag. Normal startup uses epoch rotation and cannot create an
enrollment object. Production fixes `allow_enrollment=False` with no
environment override. The first external enrollment has not been approved or
performed, and this decision does not supply the required reviewed enablement
or owner approval.

The remote namespace contract caps one generation at 250,000 objects. At
exactly one checkpoint every 300 seconds, that is about 868 days, or 2.38
years; event-driven checkpoints can consume the bound sooner. This is an
object-count safety horizon, not a startup-time SLO: full audit is linear even
though its working memory and retained proof are bounded. Before the cap is
approached, the owner must approve and test a new generation or handoff
contract. The runtime must not raise the bound or silently truncate an audit.

Every request, result, persistence projection, and worker evidence object keeps
readiness, operational-control, arming, exposure/new-exposure, broker-action,
alert-delivery, automatic-rearm/resume, paper-trading, and live-trading
authority false. External-head evidence is evidence only.

The local launcher reads only `AQT_DATABASE_URL` and the three absolute
Phase 6D source-file paths from one current-user-owned, owner-only environment
file. It rejects symlinked, multiply linked, non-owner, group/other-accessible,
oversized, or changed source files; the signing source must be exactly 32
bytes. It copies the database value, nonsecret authority, Auth secret, and raw
signing key into separate owner-only staging directories and mode-`0400`
leaves, admits their exact Compose config/secret mounts by path, metadata,
size, and in-memory digest, and waits until the supervisor has loaded all four
inputs. It then unlinks all staged leaves/directories and revalidates the
retired mounts. No secret value becomes a Compose interpolation value.

The Phase 6D image-admission contract binds the exact migration 0036 bytes,
schema head `0036_phase6_time_anchors`, and catalog relations
`phase6_trusted_time_head_anchor_intents` and
`phase6_trusted_time_head_anchor_receipts`. The final launcher/Compose/image
composition passed 103 focused tests and the actual Docker Compose verifier.
Those are local implementation proofs, not separate-project provisioning or
enrollment evidence.

## Runtime database migration observation

Migration `0036_phase6_time_anchors` adds immutable
`phase6_trusted_time_head_anchor_intents` and
`phase6_trusted_time_head_anchor_receipts`. It is additive and deliberately
does not project existing trusted-time history into an enrollment.

On 2026-08-01, the purpose-built operator's designated test-PostgreSQL proof
passed and the owner-approved runtime operation advanced
`0035_phase6_time_uncertainty` to `0036_phase6_time_anchors` transactionally.
The exact migration-file SHA-256 was
`9928c457f2593c7b3b4d6f3520eec716bb63375edb1dba3226d44d88cddcdda4`.
The retained preflight artifact-file SHA-256 was
`6a0947293540dd6ef60b2a2cc95a52aa687f47b593ac54e28a0b1ea16b2802ed`,
and the retained postflight artifact-file SHA-256 was
`92eb4d6afdac3a3725012668caf6e3df131505f028972be5f133d31b6c6c1fff`.
The postflight recorded `migration_committed=true`, no restore, the expected
catalog and full operational-schema integrity, and zero intent and receipt
rows. Do not downgrade or reinterpret that empty postflight as enrollment.

## External project provisioning observation

Separate anchor project `pgplscpqsvyraleyaphm` is Healthy on Supabase's Free
plan with its Data API disabled. Owner-only retained dashboard evidence records
the exact private `aqt-trusted-time-anchors-v1` bucket, its 4,096-byte file-size
limit, and sole `application/json` MIME allowance. This observation proves only
the visible project and bucket settings. It is not the exact SQL catalog
preflight, policy application/postflight, Auth-writer proof, Storage behavioral
proof, or runtime-artifact admission. Each of those remains `UNRUN`.

## Consequences

A later explicitly enrolled, continuously retained remote checkpoint prefix
can expose a runtime-database rollback, divergent fork, invalid signature, or
unexpected terminal head when the corresponding reconciliation runs. Durable
intent-before-upload and exact readback receipts make ambiguous network results
restart-safe without holding SQL locks over network I/O.

The implementation and runtime schema are present, and the separate project
and primary bucket have partial dashboard evidence. Exact catalog/policy
evidence, the Auth principal, real-control-bucket behavioral proof, nonsecret
authority artifact, and owner-only runtime secrets remain pending and `UNRUN`.
The first external enrollment also remains pending separate owner approval.
Until provisioning and enrollment are completed and reviewed, the deployed
topology still has no authenticated external-head evidence.

Even after enrollment, this remains same-provider, potentially same-admin
evidence rather than independent or immutable custody. It narrows some rollback
and fork risks but does not establish WORM retention, provider independence,
continuous availability, an independent watchdog, readiness, control,
exposure, alert delivery, re-arm, paper trading, or live trading.
