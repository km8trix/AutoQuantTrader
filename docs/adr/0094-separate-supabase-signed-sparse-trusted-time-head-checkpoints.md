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
namespace. Authenticated object download admits both
`storage.object.get_authenticated` and the legacy metadata operation
`object.get_authenticated_info`. Normal writer update, overwrite, and delete
operations are denied.
The upload API also sets no-overwrite semantics. These controls constrain the
runtime writer; they do not convert Supabase Storage into WORM storage or bind a
Supabase administrator.

The policy renderer admits the entire `storage.objects` policy catalog, not
only names carrying the Phase 6D prefix. Preflight accepts a completely absent
set or the complete exact expected set; postflight requires exact equality to
the expected `aqt_tt_anchor_v1_*` policies. Any unrelated, missing, or changed
policy is drift. In fresh mode the transaction creates the final policy names
directly; existing mode leaves the admitted catalog untouched. Both modes then
create each equivalent audit policy in a rollback-only PL/pgSQL subtransaction,
compare its raw `pg_policy` tree with the final policy, and deliberately abort
and catch a private sentinel before the exact whole-catalog postflight. Real
definition drift is raised outside that handler. A transaction-scoped relation
lock excludes concurrent policy DDL. This removes audit policies without
requiring owner-only rename or removal DDL on the provider-owned table. The
deployed v1 catalog omitted `object.get_authenticated_info` from its writer and
restrictive-guard SELECT operation sets. Local contract v2 corrects those two
no-reader policies and renders an exact-catalog rollback-only DROP-capability
probe followed, only if supported and separately approved, by one atomic
v1-to-v2 replacement and whole-catalog postflight.

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
public denials, and performs no cleanup. The proof does not enroll history. If
an attempt inserted its canonical object and then failed at authenticated read,
resume is allowed only from the exact canonical owner-only failure evidence;
it reuses the same proof ID, name, and payload digest and performs no fresh
insert.

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
environment override. The first external enrollment had not been approved or
performed at this ADR's acceptance, and this decision does not itself supply
the required reviewed enablement or owner approval. See the current-status
amendment below for the later confirmed ADR 0097 operation.

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

The local launcher parses exactly four assignments once from a dedicated
current-user-owned, owner-only launch environment: `AQT_DATABASE_URL` and the
three absolute Phase 6D source-file paths. Missing, duplicate, valueless,
malformed, or additional assignments fail closed. The general repository
`.env`, and any file containing application, broker, telemetry, or unrelated
credentials, is forbidden; basename `.env` is rejected before opening. The
launch environment itself must have an absolute canonical path with no
symlinked parent and be a stable, current-user-owned, single-link mode-`0600`
regular file opened by descriptor walk. The launcher rejects symlinked,
multiply linked, non-owner, group/other-accessible, oversized, or changed
source files; the signing source must be exactly 32 bytes. It copies the
database value,
nonsecret authority, Auth secret, and raw signing key into separate owner-only
staging directories and mode-`0400` leaves, admits their exact Compose
config/secret mounts by path, metadata, size, and in-memory digest, and waits
until the supervisor has loaded all four inputs. It then unlinks all staged
leaves/directories and revalidates the retired mounts. No secret value becomes
a Compose interpolation value. The read-only qualification inspector uses a
different owner-only environment containing exactly `AQT_DATABASE_URL`; it
cannot reuse either the launch file or the general `.env`, and basename `.env`
is rejected before opening.

Admission build and admission launch are separate. A secretless image build
must first run on a clean exact merged revision and retain its content-addressed
image-admission artifact. The Git boundary uses a fixed environment with
replacement refs and external configuration disabled, samples status before
and after reviewed-input validation, rejects nonordinary index flags globally,
and requires the reviewed path set, modes, and stable checkout bytes to equal
bounded `ls-tree`/`cat-file` HEAD results. Non-exempt ignored or info-excluded
additions inside reviewed source directories remain fatal.

Supported Make entry points create a fresh locked, offline uv environment,
reject the reusable repository `.venv`, run Python with `-I -B` and a
`/dev/null` bytecode-cache prefix, and attest canonical first-party source
origins before operational work. This does not independently authenticate uv,
the base interpreter, or the global uv content cache. The separately approved
2026-08-05 operator-local cache prewarm installed the exact lock graph and the
isolated runtime reported `cryptography==49.0.0`; a clean host without those
locked cache objects remains fail-closed offline.

The builder does not expose the live checkout to Docker. It constructs one
bounded deterministic tar from allowlisted HEAD blobs, validates the exact
Dockerfile-specific deny-by-default `.dockerignore`, and feeds that archive to
both direct target builds under a frozen minimal Docker environment. Each quiet
build uses the content-addressed frontend
`docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`;
the verifier rejects a mutable or different directive. It must return one exact
immutable `sha256:` ID, and all verification and
admission use those captured IDs rather than resolving mutable tags. Compose
validation consumes the exact HEAD YAML on stdin with `/dev/null` as its env
file and a fixed project directory. Image-admission v2 binds the captured build
revision alongside the IDs and reports it for review. It also binds a nonsecret
canonical Linux or macOS boot-session ID; the loader requires exact current-
session equality before applying its 15-minute monotonic freshness window.
Fresh manual approval then binds one exact tuple: the 40-character lowercase
merged Git revision, artifact SHA-256, source `sha256:` image ID, and
supervisor `sha256:` image ID.
Admission launch never
builds or rewrites the artifact. Before opening the launch environment, it
requires the exact-HEAD gate, content-addressed artifact, current reviewed
inputs, artifact freshness, installed images, rendered placeholder Compose
model, and local Docker daemon to match that tuple, then repeats the
revision/artifact gate. The approved HEAD Compose bytes are retained and used
unchanged for all runtime `up`, `ps`, and `down` commands, while non-Compose
Docker probes receive only the finite minimal pass-through environment, with
`LC_ALL` as the only admitted `LC_*` key. Runtime Compose payloads are capped
at 8,192 bytes and rendering has a 15-second timeout. Git, Docker, Compose, and
macOS boot-identity commands use command-specific streaming input/output caps
and absolute deadlines; overflow or timeout kills and reaps the isolated
process group. After staging the four inputs and immediately before Compose,
the launcher fences the daemon and repeats the revision/artifact gate again.
After the expected terminal and
verified teardown, it repeats that gate before retaining a v2 receipt. Compose
is fixed to `--no-build --pull never`, verifier runs use `--pull=never`, and
both use only the approved IDs.

Lexical validation rejects relative, noncanonical, root-equal, and outside-root
artifact paths before Git or Docker activity. Descriptor operations separately
enforce owner-only parent/file metadata.

Admission-only startup uses contract
`phase6d-unenrolled-secure-launch-admission-v2`. It requires no existing
supervisor container for the exact Compose project before opening the owner
environment. It binds the new full container ID, immutable supervisor image,
Compose project/service labels, zero restart count, and non-OOM/non-dead
terminal state. Docker state and the single terminal log line are read through
a fixed command allowlist with hard byte limits and one absolute deadline per
observation: at most 60 seconds on the normal post-validation path and two
seconds in early-failure race paths. Each bounded child reserves up to 250
milliseconds inside its supplied lifecycle deadline to kill, wait for, and
finally poll a failed subprocess. Application and broker environment values
are neither accepted by the launch file nor forwarded to those reads.

A stable complete remote audit with no retained checkpoint and production
`allow_enrollment=False` now crosses the background-thread boundary as the
fixed terminal reason
`head_anchor_remote_history_absent_enrollment_not_approved`. Provider,
configuration, integrity, and unknown failures remain outside that exact
classification and cannot satisfy this gate. Only the path that has
already validated the exact topology and mounts, observed the four-input
consumption marker, retired and revalidated all staged inputs, observed that
exact terminal reason, removed all project containers and the project network,
and revalidated the same stable creation/mount identities for both named
volumes may retain an owner-only content-addressed admission receipt. Matching
volume names and configuration alone are insufficient.
Compose-start failure or the private container-identity-disappearance race is
`secure_launch_incomplete` only when that exact expected terminal is positively
observed. A missing or unqualified terminal and every unrelated failure retain
their narrower nonzero outcomes; none can publish admitted evidence. Receipt
publication fsyncs newly created directory entries and emits the exact
canonical bytes before committing success; output failure rolls back the
just-linked receipt and fsyncs its removal. If unlink or removal durability
cannot be confirmed, fixed stderr reason `admission_retention_unconfirmed`
requires manual artifact inspection and cannot produce a zero-exit admission.
The v2 receipt binds the exact approved revision, artifact SHA-256, source image
ID, and supervisor image ID. It contains no container ID, path, timestamp,
hostname, credential, provider body, or trading authority. CLI validation of
the tuple proves only value shape and runtime correspondence; it does not prove
that the revision was merged, prove who approved it, make it single-use, impose
an approval TTL, or prevent replay. The separate manual record supplies merge
provenance and approval evidence. The receipt UUIDv4 distinguishes attempts but
is likewise not approval, trusted-time, freshness, or anti-replay evidence.

The Phase 6D image-admission contract binds the exact migration 0036 bytes,
schema head `0036_phase6_time_anchors`, and catalog relations
`phase6_trusted_time_head_anchor_intents` and
`phase6_trusted_time_head_anchor_receipts`. Its reviewed-input manifest also
binds `Makefile` and `scripts/credential_env.py`. The pre-admission-hardening
launcher/Compose/image baseline passed 103 focused tests and the actual Docker
Compose verifier. That historical result does not cover the later typed-
terminal observer, approval tuple, or v2 receipt path. The approval-binding
hardening has local verification only; its new image admission must be built
from its exact merged revision before any fresh approval or launch attempt.

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
limit, and sole `application/json` MIME allowance. On 2026-08-04, approved
provisioning SQL SHA-256
`68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
committed to that project. Read-only postflight at `2026-08-04T05:35:35Z`
proved the exact whole `storage.objects` catalog of six policies for the
dedicated writer and restrictive guards, with no reader principal or reader
policy. On 2026-08-05, the dedicated writer password was rotated and verified
through a fresh Auth sign-in. The offline generator then exclusively created
the owner-only signing key, runtime Auth secret, and nonsecret authority outside
the repository. Runtime decoders accepted the exact writer, source, deployment,
project, and private/public signing-key bindings. The secret-free receipt-file
SHA-256 is
`c52cb3eccfefed713822fe797ac5f2f93c33565b60b41940faa93b2bb30bc264`,
the authority SHA-256 is
`9747c97be9cfabf51e524eef66120e8c7ec860be18e064416b17aa197eeb8f7c`,
and enrollment remains `UNRUN` with `allow_enrollment=false`. Behavioral proof
`0396c9fe-0a8f-4b17-8c71-faa8a8033bb0` authenticated the writer, inserted one
no-overwrite canonical object, and listed it, then failed closed at
authenticated read with the provider's masked `NoSuchKey`; the object remains
and, at that point, its exact bytes had not passed authenticated GET. Canonical
owner-only failure evidence has SHA-256
`530a6ea5075ec787c16bdcbc1eb3a52e2900661e036e35ee24bb371c32f6d536`.
The exact rollback-only capability probe has SHA-256
`73f7db8b16033848cbc9790310bd7a6d4e3c4537d6a694cac9fdf368d12eea18`;
the atomic v1-to-v2 upgrade has SHA-256
`b35de9ae59438481a9f4e26bb9e18a6c3fd37eca2648f7f0ded3e6c87e0fee55`.
The probe passed under role `postgres` on 2026-08-05 and reached its terminal
rollback. Owner-only evidence SHA-256 is
`706ddc3a7a9e9f656e42b037b7e92e0dd2acd90cdd68a97d2fa4ef653bd29e81`;
its read-only postflight proved exact equality with the retained bucket and
six-policy v1 catalogs. The atomic upgrade was then approved, committed, and
postflight-verified. Owner-only applied evidence SHA-256 is
`57a4ce0914d36b179adce7f40afda99bb7bd5d859a2a9f33cb2d40984bca62e3`;
only the two SELECT policies changed, both include exact unprefixed operation
`object.get_authenticated_info`, the other four remain byte-equivalent to v1,
and the retained object and disabled enrollment state are unchanged.
On 2026-08-05, the approved same-object resume reused that exact proof ID and
canonical failure evidence. It performed no fresh canonical insert, admitted
the retained evidence, listed and read the exact retained object, and denied
the overwrite, upsert, update, delete, noncanonical-namespace insert,
real-control-bucket insert, anonymous insert/list/read, and public-read probes.
The final object and namespace were unchanged. The owner-only pass-file SHA-256
is
`85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
and its internal `evidence_sha256` is
`5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`.
Enrollment remained `UNRUN` with `allow_enrollment=false` throughout. Fresh
parse-only Compose and immutable-image admission then passed without granting
authority or new exposure. Owner-only admission artifact SHA-256
`10e7feea32ed2ad093e59f7075e60147af5fa4835986e7772262a44f64a81b07`
binds source image
`sha256:c3d81b9e1fa19b1d8131c99554da2c8ee8e6b928f27444293e82b237a24371a0`
and supervisor image
`sha256:06944ec20029fca39db5e8069f3cb3d1397333304cd6ca70343bf2c6fff312ba`.
That artifact is historical. Two later builds from merged revision
`377cb9bcc80dfeafde680097e483d2f3195f615b` and identical reviewed-input
SHA-256 `d691523d732e29c59773411e145c6462e94505b1d5e7e92e523a152b64ac9a10`
also passed image admission but produced different immutable identities.
Historical artifact
`b78bda0469077672beacbb746d0278db8b4f84dc5aead65d155c61b98ba4d0d7`
binds source
`sha256:97e8763181685663fb545bb926d3a213ffac4add3df53672ff92f9e615938810`
and supervisor
`sha256:214a627e9bc7bac9306be186bbc6f617434f337be8611edc138b067f45c3bbda`;
historical artifact
`a119b19699c4ce97a13c207d47a9c80c796194d71c99ace97489800838d1dabe`
binds source
`sha256:052439221d37672143eac652592f318c412b4b2f2948e7d20df1f84af0d7a8b9`
and supervisor
`sha256:fa22b4b58474204f25e10281e224bdb5fdc184cce52ccc730948685a3fad04db`.
These three, like every currently retained canonical or content-addressed
`image-admission*.json` artifact, use a superseded v1 image-admission schema,
omit the captured `git_revision`, and are historical evidence only; the current
v2 loader rejects them.
The drift is permitted and demonstrates why every rebuild needs a new approval
tuple. A subsequent secure-launch attempt did not admit and retained no v2
receipt; secure-launcher runtime admission is `ATTEMPTED_NOT_ADMITTED`.
Enrollment remains `UNRUN`. No retry is permitted until this hardening is
merged, new images are built from that exact merge, and the owner approves the
new revision/artifact/image tuple.

### Current-status amendment (2026-08-08)

The preceding observations are historical. The hardening was merged, fresh
immutable images and fail-closed admission were retained, and ADR 0097's one
separately approved `new` operation confirmed the first external checkpoint at
sequence 1. Its owner-only claim and confirmed outcome are retained, and no
sequence 2 exists. ADR 0098 now authenticates that exact historical evidence
without granting authority. Persistent start and graceful shutdown remain
quarantined pending the separately reviewed outcome-bound runtime contract; no
repeat enrollment or automatic recovery is authorized.

## Consequences

A later explicitly enrolled, continuously retained remote checkpoint prefix
can expose a runtime-database rollback, divergent fork, invalid signature, or
unexpected terminal head when the corresponding reconciliation runs. Durable
intent-before-upload and exact readback receipts make ambiguous network results
restart-safe without holding SQL locks over network I/O.

The implementation and runtime schema are present. The separate project,
primary and real control buckets, exact catalog/policy evidence, and dedicated
Auth principal are retained. The writer password has been rotated and verified,
and the owner-only runtime artifacts plus nonsecret authority have been
generated and decoder-validated. The real-control-bucket behavioral proof is
complete: its retained initial authenticated-read failure led to the exact
two-policy correction, and the evidence-bound same-object resume then passed
without a fresh insert or namespace change. Fresh parse-only Compose and
historical immutable-image admissions are retained. The later ADR 0097
operation confirmed the first external checkpoint and ADR 0098 authenticates
its retained evidence. The system therefore has historical authenticated
external-head evidence at sequence 1, but no approved persistent runtime,
sequence 2, graceful-stop successor, or independent terminal observer.

Even after enrollment, this remains same-provider, potentially same-admin
evidence rather than independent or immutable custody. It narrows some rollback
and fork risks but does not establish WORM retention, provider independence,
continuous availability, an independent watchdog, readiness, control,
exposure, alert delivery, re-arm, paper trading, or live trading.
