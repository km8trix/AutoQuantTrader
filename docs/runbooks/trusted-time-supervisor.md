# Trusted-time supervisor

This runbook describes the evidence-only local Chrony NTS topology established
by historical
[ADR 0092](../adr/0092-evidence-only-local-chrony-nts-trusted-time-supervision.md)
and its completed System76 authority rotation in
[ADR 0093](../adr/0093-system76-virginia-nts-authority-rotation.md). The
implemented but not yet externally enrolled sparse-head checkpoint boundary is
defined by
[ADR 0094](../adr/0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md).
The dormant pure watchdog-state transition is defined by
[ADR 0095](../adr/0095-dormant-provider-neutral-trusted-head-watchdog-state.md);
it is not deployed and changes no procedure in this runbook.
ADR 0092's exact Netnod authority is preserved as the
[archived v1 manifest](../adr/evidence/0092-source-authority-v1.json), SHA-256
`356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab`.
The current normative nonsecret pins are the checked-in
[source-authority manifest](../../infra/trusted-time/source-authority.json) and
[Chrony configuration](../../infra/trusted-time/chrony.conf), plus the
[pinned Supabase root CA](../../packages/persistence/certs/supabase-prod-ca-2021.crt).
Do not replace their values with environment overrides.

Migration `0035_phase6_time_uncertainty` was applied and postflight-verified on
runtime Supabase on 2026-08-01. The first directly supervised Cloudflare/Netnod
window was retained as immutable historical `not_qualified` evidence. The
Cloudflare/System76 v2 implementation and immutable images were subsequently
admitted, and a separate directly supervised inspector-v5 window qualified.
Migration `0036_phase6_time_anchors` was then applied and postflight-verified
on 2026-08-01 with zero anchor intents and receipts. The separate anchor
project and exact primary bucket now have retained dashboard evidence, but SQL
catalog/policy proof, the Auth writer, behavioral proof, runtime artifacts, and
the first external enrollment remain `UNRUN`.
Neither migration nor either inspected window grants readiness or any trading
authority.

This topology always reports readiness, operational-control, arming,
exposure/new-exposure, broker-action, alert-delivery, automatic-rearm/resume,
paper-trading, and live-trading authority as false. A healthy clock or signed
external checkpoint does not change any of them.

## Implemented v2 local topology

- Authority contract: `phase6c-local-chrony-nts-authority-v2`.
- Source ID: `chrony-nts-cloudflare-system76-virginia-v2`.
- Adapter contract: `phase6-chrony-4.8-nts-evidence-v2`.
- Host ID: `local-paper-docker-primary-v1`; no failover or host rotation.
- Source daemon: Chrony 4.8 with `-x`, using exactly
  `time.cloudflare.com` and `virginia.time.system76.com` over NTS.
- Adapter: one fixed C-locale `chronyc` monitoring transaction through the Unix
  socket, beginning with `retries 0`, with negotiated NTP UDP port 123 for each
  source.
- Composite: exactly one selected and one combined source; both required,
  authenticated, selectable, and fresh, with a normal aggregate leap state.
- Schedule: one immediate durable probe followed by an absolute monotonic
  20-second grid; one-second probe deadline, no retries, and no catch-up burst.
- Source uncertainty: at most 100 milliseconds. Health uses
  `abs(point offset) + uncertainty` against `<250`, inclusive `250-1,000`, and
  `>1,000` millisecond bands.
- Persistence: runtime Supabase through the Compose secret. Migration 0036 has
  installed the local anchor intent/receipt schema, but no externally enrolled
  head exists. Psycopg uses exact `verify-full` hostname/chain verification
  against the checked-in CA, never a default trust path.
- Resources: local Docker CPU/RAM only. The source is limited to 0.25 CPU and
  64 MiB; the supervisor is limited to 0.5 CPU and 256 MiB.

System76 publishes no SLA, upstream time-source ensemble, deployment-
redundancy commitment, or leap-smear policy for the Virginia endpoint. Do not
infer any of those properties from endpoint reachability or a successful
sample. This remains best-effort, evidence-only local supervision, and every
authority flag remains false. The separately reviewed v2 authority manifest,
Chrony configuration, adapter, inspector-v5 contract, and immutable images are
implemented and admitted, and the retained point-in-time live window qualified.
That result does not establish an availability, SLA, upstream-ensemble,
redundancy, or leap/smear guarantee.

Both containers run as UID/GID 10001 on read-only root filesystems with all
capabilities dropped and `no-new-privileges`. The source exposes no port, has
no `SYS_TIME`, and cannot set the host clock. Only a dedicated ephemeral,
mode-0750 Chrony command-socket tmpfs is shared read-write: unmodified Chrony
4.8 requires `chronyc` to create a short-lived reply socket beside the daemon
socket. Chrony's state volume remains source-only.

## Implemented Phase 6D contract; external provisioning incomplete

The Phase 6D code and runtime-database schema are implemented. Separate anchor
project `pgplscpqsvyraleyaphm` is Healthy on Supabase's Free plan with its Data
API disabled. Owner-only retained dashboard evidence records its exact private
`aqt-trusted-time-anchors-v1` bucket, 4,096-byte size limit, and sole
`application/json` MIME allowance. That does not prove the SQL catalog or
policies. The exact catalog preflight/policy apply, dedicated Auth writer,
behavioral proof, signing/Auth/authority artifact creation, and enrollment are
all `UNRUN`. No first enrollment has been approved or performed. Do not
describe the current deployment as externally anchored.

The exact implemented identities and bounds are:

- provider-neutral contract
  `phase6d-provider-neutral-external-trusted-head-anchor-v1`;
- deployment-authority contract
  `phase6d-separate-supabase-trusted-head-authority-v1`;
- Supabase adapter contract
  `phase6d-separate-supabase-storage-anchor-adapter-v1`;
- durable SQL contract
  `phase6d-durable-trusted-time-head-anchor-persistence-v1`;
- single-flight worker contract
  `phase6d-single-flight-trusted-head-anchor-worker-v1`;
- exact private bucket `aqt-trusted-time-anchors-v1` in a Supabase project
  distinct from both runtime and test projects;
- an absolute 300-second checkpoint grid and stale evidence at 360 seconds or
  greater, including equality; and
- a remote-namespace bound of 250,000 objects, about 868 days or 2.38 years at
  exactly one checkpoint per grid interval and less with event checkpoints;
  this is an object-count horizon, not a startup-time service-level objective.

The supervisor's fixed container paths are:

- nonsecret authority:
  `/etc/autoquant/trusted-time/head-anchor-authority.json`;
- owner-only Supabase Auth secret:
  `/run/secrets/trusted_time_head_anchor_auth`; and
- raw 32-byte Ed25519 private key:
  `/run/secrets/trusted_time_head_anchor_signing_key`.

Compose fixes those container paths with
`AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH`,
`AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE`, and
`AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE`. Their host-side Compose source
variables are respectively
`AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE`,
`AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE`, and
`AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE`. The checked-in
defaults deliberately set all three sources to `/dev/null` for parse-only
admission. At runtime, the secure launcher replaces all four `/dev/null`
sentinels with fresh protected staging paths after loading only
`AQT_DATABASE_URL` and the three source-path variables from one explicit
owner-only environment file. The three source files must be absolute,
current-user-owned, non-symlinked, single-link regular files with no group or
other access; their contents must be stable and within the exact bounds, and
the signing-key source must contain exactly 32 raw bytes. Do not export ad hoc
Compose overrides around this launcher.

Never put the Auth password, session token, or private key in a checked-in
environment file, authority JSON, command argument, image layer, log, or
retained artifact. The authority JSON contains only the admitted Ed25519 public
key and digest, key ID, project and principal identities, bucket,
source/host/runtime binding, checkpoint policy, and false authority flags.

Runtime composition uses a separate bounded database engine with pool size one
for anchor SQL so provider work cannot consume the local probe repository's
connection. After a fresh epoch registration, the startup path consumes the
complete local journal and durable intent/receipt history in bounded pages
inside one repeatable-read SQL snapshot. It lists and downloads the complete
remote prefix in bounded pages on one background thread, authenticates each
record without retaining the whole prefix, and performs a second listing/hash
pass to reject namespace drift. Explicit on-demand work performs the same
complete local, durable, and remote audit. Provisional pages are released and
only a constant-size sealed proof/tip is retained. Working memory is bounded,
but full-audit work and provider calls are linear in retained history and have
no promised startup-time bound at the maximum horizon.

Periodic and transition work uses the compact authenticated tip to verify only
the exact terminal and exact next remote sequence plus a new local suffix.
That incremental check does not prove arbitrary middle-row retention; require
a startup/on-demand full audit for that property.

One new checkpoint must commit its immutable SQL intent before remote I/O,
upload with no overwrite, authenticate the provider reconciliation readback,
download the object a second time, and seal that exact provider-`GET` identity
and payload in an application-issued, single-use evidence object. Persistence
accepts only that sealed evidence before it commits the receipt; a caller
cannot construct it or substitute locally retained candidate bytes. Recover
one pending intent before any successor after a restart or ambiguous provider
result. Only a positively classified provider outage or the typed,
authenticated local-head compare-and-swap advance is retryable. Treat
signature, fork, rollback, identity, configuration, persistence, malformed
provider response, and every unclassified failure as fatal.

Production composition currently passes `allow_enrollment=False`; there is no
environment toggle that can weaken it. Sequence 1 requires reason
`enrollment`, a complete audit, separately reviewed runtime enablement, and
explicit owner approval. Do not use epoch rotation, a manual database insert,
an object upload, or a policy change to bypass that gate.

Even after enrollment, this is separate-project evidence on the same provider
and potentially under the same administrator. Supabase Storage is not WORM,
and administrator/provider privileges are not constrained by the runtime Auth
writer's row-level policies. Keep the external signer key outside Supabase,
retain the limitation in every review, and plan and test a separately approved
generation/handoff before the 250,000-object cap. Do not interpret bounded
working memory or the object cap as a startup-time SLO; a complete audit remains
linear and event checkpoints can consume the horizon sooner.

## Dormant Phase 6E watchdog-state contract

Contract `phase6e-provider-neutral-trusted-head-watchdog-state-v1` is a pure,
preparatory state transition only. It is deliberately absent from the Compose
profile and has no operator command. Raw signed checkpoint bytes and
caller-supplied monotonic values remain untrusted candidates. Signature and
chain authentication do not prove provider origin, the current remote terminal,
absence of a higher sequence, remote advancement, stop state, freshness,
liveness, or an independent observation instant.

The reducer never reports `CURRENT` or `STOPPED` and never calculates
staleness from caller input. Every nonfatal result is `UNAVAILABLE` with
`STARTUP_NO_BASELINE`, `BASELINE_ONLY`, `PROVIDER_TERMINAL_PROOF_ABSENT`, or
`PROVIDER_UNAVAILABLE`. An exact signed gap-free successor, including
`clean_stop`, advances only chain diagnostics. Its sealed output is bound to
the contract and exact authority, but no consumer exists.

Malformed checkpoints, invalid signatures, identity mismatch, fork, rollback,
gap, predecessor mismatch, and caller-clock regression fail closed. All
authority flags remain false.

Do not operate or describe this library contract as a watchdog deployment. It
contains no Supabase/provider adapter, runtime process/container, independent
failure domain, alert delivery, readiness/control/new-exposure/manual-re-arm
integration, deployment, drill, or Phase 6 exit evidence. The required order
is still:

1. complete the separate Supabase anchor project's remaining provisioning and
   retain reviewed catalog, policy, principal, artifact, and behavioral evidence;
2. separately obtain approval for and retain the first enrollment evidence;
3. only then implement a sealed provider-terminal issuer that authenticates a
   complete new suffix, binds two stable namespace passes to their exact
   digest/count/terminal identity, proves no higher sequence exists, and
   captures its own independent monotonic instant; and
4. only after that issuer is reviewed may a separate runtime apply the
   360-second stale threshold, with equality stale and every stale result
   unavailable, and qualify later consumers.

Until those steps occur, the current operational instruction remains direct
observation: a stopped supervisor is not independently detected or alerted.

## Qualification prerequisites

Before any new approved qualification window:

1. Require a clean, reviewed commit and record its exact revision. Confirm the
   manifest, Chrony config, Dockerfile, Compose file, migration, lock file, and
   supervisor source all come from that revision.
2. Keep the owner-controlled Supabase DSN outside the repository and out of
   command arguments, shell history, logs, and retained evidence. Its only
   query option must be `sslmode=verify-full`; missing, weaker, duplicated, or
   additional options fail closed. Do not add `sslrootcert` to the DSN. The
   host preflight and migration command validate the exact checked-in CA hash;
   the supervisor uses the root-owned image copy at the manifest-pinned path.
   Docker Compose must receive the DSN through the
   `trusted_time_database_url` secret.
3. Query runtime Supabase without printing the DSN. Require revision
   `0036_phase6_time_anchors` and pass the full operational-schema, trusted-time
   replay-integrity, and anchor-table catalog gates. Preserve every existing
   Netnod/System76 epoch, evaluation, and host-head predecessor as immutable
   history. Until separately approved enrollment occurs, require zero anchor
   intent and receipt rows.
4. Do not rerun migration 0035 or 0036 for a provider rotation. The System76
   rotation changed neither the 100-millisecond policy nor its schema;
   migration 0036 separately added only the external-anchor intent/receipt
   boundary. Require a fresh process epoch after the exact implementation and
   images are admitted; prior-authority or prior-epoch samples and failures
   cannot count toward its window.
5. Confirm the local Mac is awake, connected to power, and directly observed.
   There is no external alert, independent heartbeat, or deployed stale-host
   watchdog. The dormant pure Phase 6E state contract does not change this.
6. Confirm only the required outbound DNS, NTS-KE on TCP 4460, and negotiated
   provider NTP egress on UDP 123 for Cloudflare and System76 Virginia is
   permitted. Do not publish an inbound port.

The earlier 2026-07-31 observation covered migration 0034 and empty tables.
The retained 2026-08-01 migrations 0035/0036 postflights and Netnod live-window
artifact supersede that status but remain historical. ADR 0093's separately
implemented System76 v2 authority and retained inspector-v5 result satisfy the
exact image and live-evidence gates for that point-in-time window; they do not
make the old Netnod artifact successful or authorize any consumer. Migration
0036's zero anchor rows likewise prove only schema deployment, not external
enrollment.

### Historical migration 0035 procedure

This procedure records how the already-applied migration was operated. Do not
rerun it for the System76 source rotation.

Do not use raw Alembic commands for the runtime transition. From the repository
root, run the purpose-built operator with one absolute current-user-owned,
non-symlinked mode-`0400` or mode-`0600` environment file. Its runtime and test
bindings must be distinct exact Supabase Session-pooler DSNs using only
`sslmode=verify-full`. Store evidence at new absolute paths in an existing,
non-symlinked, owner-only directory outside the repository:

```console
.venv/bin/python scripts/migrate_phase6_trusted_time_uncertainty.py \
  check-bindings
.venv/bin/python scripts/migrate_phase6_trusted_time_uncertainty.py \
  test-postgres \
  --env-file /absolute/path/to/owner-only.env
.venv/bin/python scripts/migrate_phase6_trusted_time_uncertainty.py \
  preflight-runtime \
  --env-file /absolute/path/to/owner-only.env \
  --artifact /absolute/path/to/owner-only-evidence/phase6-0035-preflight.json
.venv/bin/python scripts/migrate_phase6_trusted_time_uncertainty.py \
  apply-runtime \
  --env-file /absolute/path/to/owner-only.env \
  --preflight-artifact \
    /absolute/path/to/owner-only-evidence/phase6-0035-preflight.json \
  --postflight-artifact \
    /absolute/path/to/owner-only-evidence/phase6-0035-postflight.json
```

Require the offline binding check and isolated test-PostgreSQL proof to pass.
The runtime preflight must authenticate exact revision
`0034_phase6_trusted_time`, TLS, the expected pre-0035 catalog, and zero rows in
all three trusted-time tables. Review its canonical mode-`0600` artifact and
obtain explicit owner approval immediately before applying it; the artifact is
valid for only 15 minutes. The apply command rechecks every binding and live
fact, takes an advisory transaction lock, executes only
`0035_phase6_time_uncertainty`, verifies its exact postflight catalog and full
operational schema, and writes a separate mode-`0600` postflight artifact.

Stop on any nonzero exit. An error with `migration_committed=true` requires a
catalog review, not a blind retry. Do not use `alembic upgrade head`, downgrade
0035, or point the migration operation at `AQT_TEST_POSTGRES_URL`. These
commands remain the procedure for a separately approved fresh deployment; do
not reapply them to the now-nonempty current runtime. The current retained
mode-`0600` postflight artifact SHA-256 is
`73085244cad0c24f22a06b22e8cf106c26f9e69a3bf5b32b9a296e995e165e6a`.

### Historical migration 0036 procedure

This procedure records the already-completed additive anchor-schema operation.
Do not rerun it on the current runtime.

From the repository root, the purpose-built operator used the same exact
owner-only environment/TLS restrictions as migration 0035 and the following
sequence:

```console
.venv/bin/python scripts/migrate_phase6_trusted_time_head_anchors.py \
  check-bindings
.venv/bin/python scripts/migrate_phase6_trusted_time_head_anchors.py \
  test-postgres \
  --env-file /absolute/path/to/owner-only.env
.venv/bin/python scripts/migrate_phase6_trusted_time_head_anchors.py \
  preflight-runtime \
  --env-file /absolute/path/to/owner-only.env \
  --artifact /absolute/path/to/owner-only-evidence/phase6d-0036-preflight.json
.venv/bin/python scripts/migrate_phase6_trusted_time_head_anchors.py \
  apply-runtime \
  --env-file /absolute/path/to/owner-only.env \
  --preflight-artifact \
    /absolute/path/to/owner-only-evidence/phase6d-0036-preflight.json \
  --postflight-artifact \
    /absolute/path/to/owner-only-evidence/phase6d-0036-postflight.json
```

The designated test-PostgreSQL proof passed before runtime preflight. The
operator authenticated exact prior revision `0035_phase6_time_uncertainty`,
migration SHA-256
`9928c457f2593c7b3b4d6f3520eec716bb63375edb1dba3226d44d88cddcdda4`,
the pinned TLS and database bindings, the additive catalog, and full
operational-schema integrity. Its preflight was valid for only 15 minutes.

The owner-approved apply committed `0036_phase6_time_anchors` transactionally;
the operator result reported `migration_committed=true` and no restore was
performed or available. The retained preflight artifact-file SHA-256 is
`6a0947293540dd6ef60b2a2cc95a52aa687f47b593ac54e28a0b1ea16b2802ed`.
The retained postflight artifact-file SHA-256 is
`92eb4d6afdac3a3725012668caf6e3df131505f028972be5f133d31b6c6c1fff`;
it authenticates revision 0036, the exact two-table catalog, the full
operational schema, and zero intent/receipt rows.

For any separately approved fresh deployment, stop on a nonzero exit. An error
reporting `migration_committed=true` or an unknown commit outcome requires a
read-only catalog review and forward-fix decision, never a blind retry. Do not
use raw Alembic upgrade/downgrade as a substitute, and do not treat empty
anchor tables as permission to enroll.

## Separate anchor project provisioning gate

This gate is in progress and remains incomplete. Project
`pgplscpqsvyraleyaphm` is Healthy on Supabase's Free plan with its Data API
disabled. Owner-only retained dashboard evidence records the exact private
primary bucket `aqt-trusted-time-anchors-v1`, its 4,096-byte file-size limit,
and sole `application/json` MIME allowance. Dashboard evidence is not an exact
SQL catalog or policy proof, and none of the remaining steps below has been
run. Partial or complete provisioning does not approve enrollment.

1. The distinct anchor project and primary bucket creation are complete only at
   the dashboard-evidence layer described above. Continue to record only
   identity digests and nonsecret project refs in reviewed evidence. Never
   insert or update `storage.buckets` directly.
2. Create a dedicated Supabase Auth writer. Do not supply the service-role key
   to the runtime. If a separate reader is approved, bind its distinct Auth
   UUID explicitly; otherwise omit it.
3. Use
   `scripts/provision_trusted_time_anchor_project.py` to validate the three
   distinct project refs, exact project URL, publishable key, and principal
   UUIDs and to render the deterministic
   `aqt-trusted-time-supabase-anchor-project-v1` SQL. Review its digest before
   applying it to the separate project. The transaction must find the exact
   pre-created bucket. Its catalog gate examines the entire policy set on
   `storage.objects`: preflight accepts only no policies or the complete exact
   expected set, and postflight requires the entire set to be exactly the
   expected `aqt_tt_anchor_v1_*` policies. Any unrelated policy is drift. Retain
   exact preflight, apply, and postflight evidence.
4. Through the supported dashboard or API, create and retain independent
   owner-only evidence for a real, distinct private control bucket in this same
   project. It must not be `aqt-trusted-time-anchors-v1`, and it receives no
   writer policy. This bucket exists only to prove cross-bucket denial; a
   nonexistent name is not evidence of authorization behavior.
5. Run `scripts/generate_trusted_time_anchor_artifacts.py` offline to create one
   raw 32-byte Ed25519 private key, one exact runtime-compatible Auth-secret
   JSON, and one nonsecret authority JSON. Use absolute, distinct owner-only
   targets outside Supabase and outside the repository. The operator refuses
   overwrite, validates all three against runtime contracts, emits only a
   secret-free receipt, fixes `allow_enrollment=false`, and records enrollment
   `UNRUN`. Never place the password, Auth secret, or signing key in reviewed
   evidence.
6. Run `scripts/prove_trusted_time_anchor_storage.py` with the owner-only Auth
   secret and the retained real-control-bucket evidence. It authenticates the
   exact writer and retains one synthetic canonical object under a proof-only
   deployment/host prefix outside the runtime's exact prefix. It must prove the
   writer can list/read and insert only names matching
   `v1/<deployment-sha256>/<host-sha256>/<20-digit-sequence>-<sha256>.json`.
   Require strict authorization denial for overwrite, upsert, update, delete,
   unrelated namespaces, the evidenced real control bucket, and anonymous
   insert, plus denial or provider masking for the positively established
   private object's anonymous/public read routes. Preserve only its sanitized
   result; never retain access tokens, passwords, or provider response bodies.
   The operator has no cleanup mode: the synthetic proof object remains, while
   enrollment stays `UNRUN`.
7. Retain the parse-only Compose admission with all four runtime sources at
   `/dev/null`, then use only the implemented secure launcher to stage, admit,
   and retire the exact database, authority, Auth, and signing-key mounts
   without exposing their contents. Confirm the production composition still
   fixes `allow_enrollment=False` with no environment override, then stop and
   request separate owner approval for any reviewed one-time enrollment
   enablement and operation.

Administrator/provider access can bypass these writer policies. Record that
the result is same-provider and potentially same-admin evidence, not WORM or
independent custody.

## Offline review and build

Use the deliberately empty Compose interpolation file so Docker Compose does
not load an owner credential file implicitly:

```console
make trusted-time-compose-check
make trusted-time-images
```

The first command validates the rendered service allowlist, config/secret
mounts, resources, privileges, and absence of inbound ports. It requires the
database secret, Phase 6D authority config, Auth secret, and signing-key source
variables to use the checked-in parse-only `/dev/null` sentinels. The second
builds both targets and verifies their immutable metadata, exact Chrony/config
bytes, the exact root-owned CA bytes, NTS-enabled version, secretless
fail-closed result, and lack of embedded credentials. Before invoking Compose
build it renders and admits that exact sentinel model. It then atomically
writes the canonical
`artifacts/trusted-time/image-admission.json` artifact with mode `0600` below
owner-only directories. The artifact binds the exact source and supervisor
image IDs to the checked-in Dockerfile, Compose/config/authority, pinned CA,
migration 0036 bytes, schema head `0036_phase6_time_anchors`, catalog relations
`phase6_trusted_time_head_anchor_intents` and
`phase6_trusted_time_head_anchor_receipts`, dependency lock, and reviewed
supervisor/package source digest under contract
`phase6d-trusted-time-image-admission-v1`.
Docker Desktop must be running locally; a Compose parse alone is not build or
runtime evidence.

Treat these commands as unperformed for each new reviewed revision until they
are run on that exact revision. Retain the admission artifact and its two
immutable image IDs, not only the mutable `phase6d-v1` tags. Equivalent Docker
builds are not required to produce the same image ID; never compare a new build
to a prior ID or admit a running arbitrary ID. Verify from image metadata and the rendered
Compose model that:

- the source runs `/usr/sbin/chronyd -x -d -U` with the pinned config;
- both images contain the expected Chrony 4.8 executable and config digest;
- the supervisor contains the exact CA SHA-256 from ADR 0092 with metadata
  `0:0:0444`;
- neither service publishes a port or adds a capability;
- both services use UID/GID 10001, read-only roots, `no-new-privileges`, and the
  reviewed CPU, RAM, PID, and temporary-filesystem limits; and
- the supervisor sees only the dedicated command-socket scratch volume, one
  exact Phase 6D authority config target, and exactly the database, anchor Auth,
  and raw signing-key secret targets; and
- parse/build admission keeps all four host source files at `/dev/null` and
  cannot be mistaken for provisioned runtime admission.

The final Phase 6D launcher/Compose/image composition passed 103 focused tests
and the actual Docker Compose verifier. That is implementation evidence only;
it is not a fresh immutable-image admission for another revision, separate-
project provisioning evidence, or enrollment evidence.

Any mismatch stops qualification. Do not retag or patch a running container to
make it pass.

Plan and complete CA rotation before `2031-04-26T10:56:53Z`. Treat rotation as
a new reviewed authority/image pair and prove one real `verify-full`
connection to the intended Supabase Session-pooler hostname before use.

## Approval-blocked supervised start

This section remains approval-blocked because the separate-project
provisioning gate is `UNRUN`, production composition fixes
`allow_enrollment=False`, and no first enrollment has been approved or
performed. The secure launcher is implemented; its presence does not provision
the external project or approve enrollment. A start must fail closed when the
exact authority/secrets are absent or the remote prefix is unenrolled. Do not
run `make trusted-time-start` as a provisioning experiment and do not weaken
that behavior to repeat the earlier source-only window.

The launcher freshly builds and verifies both images, atomically replaces the
canonical owner-only image-admission artifact, reloads its canonical bytes and
current reviewed-input digest, and renders the exact immutable IDs before it
opens the environment file. It rejects a symlinked, non-owner,
broader-than-0600, oversized, or duplicate-variable environment file and
extracts only `AQT_DATABASE_URL` plus the three absolute Phase 6D source-file
paths. Alpaca, Sentry, and other application credentials are never forwarded.

After those secretless gates, the launcher creates four fresh mode-`0700`
directories below ignored `artifacts/trusted-time/runtime-secrets`. It writes
the exact database value, nonsecret authority, Auth secret, and raw signing key
through exclusive non-symlink file descriptors, fsyncs them, and changes each
leaf from mode `0600` to `0400`. Compose receives only the four staged absolute
paths; no secret content is a Compose interpolation value. The launcher
requires the exact read-only config/secret source and target for every input
and the container-visible `10001:10001:0400` metadata, size, and in-memory
SHA-256.

The fixed nonsecret consumption marker is written only after the supervisor
has loaded the database, authority, Auth, and signing-key inputs. The launcher
then validates the full topology, unlinks all four host leaves and removes
their per-run directories, and proves each retired mount has an admitted
outcome. Native Linux may retain the exact readable inode and digest; Docker
Desktop instead makes reads fail with no output after host unlink. A successful
read of changed bytes is rejected. The supervisor uses `restart: no`, so an
exited process cannot re-read or restart from a retired mount. Any failure
stops the attempted topology; cleanup failure is fatal. Do not place any
secret on a command line or copy it into `trusted-time.defaults.env`.

After retained separate-project provisioning evidence and a separately
approved, reviewed first enrollment, the normal post-enrollment start is:

```console
make trusted-time-start ENV_FILE=/absolute/path/to/owner-only.env
```

The first enrollment needs its own reviewed enablement because production is
hard-wired to deny it; the normal command above cannot create sequence 1.

### Requirements after the start gate is reopened

The following source/probe checks become current only after retained Phase 6D
provisioning and enrollment evidence reopens the start gate. They also describe
the already retained historical Phase 6C windows.

Keep the terminal and Docker runtime directly observed. The Chrony healthcheck
only proves that its local command socket responds; it is not NTS/source
admission or clock-health evidence.

Require the supervisor's first durable attempt immediately after its fresh
epoch registration. Then require attempts on the original absolute 20-second
monotonic grid. Completion time must not slide the grid, and a late wake must
not cause retries or a catch-up burst.

For every recorded sample, verify through secret-safe database inspection that:

- source/authority/host/epoch identities match the checked-in manifest;
- the source set is exactly Cloudflare plus System76 Virginia, with one selected
  and one combined source, authenticated NTP packets, an admitted NTS AEAD/key
  pair, normal leap and NTPv4 server state, fixed 16-second polling, passing
  source tests, negotiated NTP UDP port 123, and reference age no greater than
  30 seconds;
- source uncertainty is an exact decimal no greater than 100 milliseconds;
- the persisted health band uses point-offset magnitude plus uncertainty; and
- immutable evaluation and host-head chains replay through the public reducer.

Do not retain database credentials or raw command output beyond the reviewed
evidence fields. A successful sequence remains evidence-only and must leave
every authority false.

## Live qualification inspection

The inspector-v5 procedure qualifies only the local Chrony/source/process/
persistence window. It does not provision, enroll, or qualify the Phase 6D
external anchor and continues to report external-head authority false. Do not
use its exit status or artifact as anchor provisioning/enrollment evidence.

Keep the topology directly observed until the current process epoch contains
at least four recorded attempts on the immediate/20-second grid and has had
enough time to prove the continuous 60-second recovery interval. Then run the
read-only inspector from the same reviewed repository checkout. The artifact
directory must be the absolute path to a descendant of that checkout's ignored
`artifacts/` directory; the inspector rejects symlinked paths and creates its
directories owner-only:

```console
make trusted-time-inspect ENV_FILE=/absolute/path/to/owner-only.env
```

The inspector loads only `AQT_DATABASE_URL`, revalidates the exact Supabase
Session-pooler and pinned-CA contract, runs the full operational-schema and
trusted-time replay-integrity gates, and holds a read-only repeatable-read
snapshot for host `local-paper-docker-primary-v1`.

Before inspecting any image or container, the inspector resolves the effective
Docker endpoint selected by `DOCKER_HOST`, `DOCKER_CONTEXT`, or the active
context. The endpoint must canonicalize to an existing local Unix socket owned
by root or the current user and must not be world-writable. TCP, SSH, HTTP, and
other remote endpoints are rejected before daemon contact. The inspector binds
the context, canonical socket endpoint, and Docker daemon ID in memory, then
requires that exact local-daemon identity immediately before and after its
container and clock rechecks. A daemon, context, or endpoint change fails the
inspection; none of those private daemon details enter the artifact.

Before reading the database secret, the inspector opens the same canonical
launch admission through an owner-only, mode-`0600`, regular, single-link,
non-symlink file descriptor. It rejects noncanonical bytes, duplicate or extra
fields, stale host-monotonic creation evidence (the artifact is valid for 15
minutes), a current reviewed-input mismatch, or a changed artifact between
identity fences. It fully re-runs image verification against only the two
artifact-bound immutable IDs without rebuilding. It then requires the two
running Compose containers to use exactly those IDs; it never treats an
arbitrary running ID as a candidate for re-admission. The recorded per-run host
secret leaf and parent must both remain absent, independently proving launcher
cleanup. Before
reading the database, it also authenticates the running containers' exact
command, entrypoint, environment allowlist,
capabilities, network, resources, healthcheck, restart policy, volumes, secret
mount metadata, and protected runtime-path metadata between container and daemon
identity fences. This inspection never opens or serializes the database secret.

The process binding is the container-PID1 lifecycle (Compose enables
`init: true`), not Docker `StartedAt`. In one bounded in-container read per
service, the inspector binds `/proc/1/stat` field 22 to the reader process,
requires PID1 `time_for_children`, PID1 time, and reader time namespaces to be
identical within that container, and proves exact zero `monotonic` and
`boottime` offsets for both PID1 and reader. The source and supervisor may have
different namespace inode IDs, as Docker Desktop does, but both IDs are retained
as drift fences, both offset sets must remain zero, and their kernel boot UUID
must match. Exact `CLK_TCK=100` remains mandatory. After the database snapshot,
the inspector rechecks all values and reads `CLOCK_BOOTTIME` in the same exact
Python process that proves its own zero offsets, then repeats the full topology,
image, process, clock, and daemon fences. This avoids comparing the Docker VM's
boot-time clock to the workstation's unrelated monotonic clock or pairing
database history with a changed process or time domain.

Its canonical JSON contains only counts, current health/reason and sequence,
bounded timing gaps/spans and terminal age, uncertainty bounds, fixed
identities, authority/config/database hashes, admitted/process-bound flags, and
image IDs. It contains no DSN, database hostname, credential, container ID,
container start time, epoch registration time, absolute sample time, or raw
`chronyc` payload. `--minimum-evaluations` may make the inspection stricter but
cannot reduce the fixed four-recorded-sample floor.

Exit status 0 and `status=qualified` require at least four **recorded** samples,
accepted cadence/span evidence, terminal `health=healthy`,
`reason=within_limit`, `hard_failure_latched=false`, and
`clock_recovery_qualified=true`. The terminal evaluation must also be no more
than 30 seconds old on the current supervisor's `CLOCK_BOOTTIME`. On the shared
authenticated boot with exact zero time offsets, the source container PID1
start tick must be strictly earlier than the supervisor container PID1 start
tick, and the current epoch's first evaluation monotonic value must be at or
beyond the conservative exclusive upper edge of the supervisor's start-tick
interval. The
current `CLOCK_BOOTTIME` must also be at or beyond that edge. The freshly built
image pair and live topology must pass admission. A source or supervisor
container restart therefore invalidates the prior epoch/window until a fresh
ordered topology records the complete qualifying window. Earlier failed
attempts remain visible in the status counts and do not count toward the four
recorded samples. Every manifest authority remains false; qualification never
authorizes readiness, control, exposure, alerts, re-arm, paper trading, or live
trading.

Exit status 3 means the persisted evidence was structurally inspectable but
the window was `not_qualified`; its failure counts and terminal state are still
printed and retained. Exit status 2 means the inspection or artifact boundary
failed. In both the qualified and not-qualified cases, the mode-`0600` artifact
contains exactly the same canonical bytes printed to standard output and is
named by its qualification SHA-256. Do not use shell redirection to create a
second evidence copy, and do not treat either nonzero status as success.

Regardless of the inspector result, proceed directly to the clean-stop
procedure below. A failed or incomplete window is not a reason to leave the
local topology unattended or to retry automatically. For any future revision
or epoch, the command and artifact remain `UNRUN` until they are actually
executed and reviewed.

## Retained historical 2026-08-01 Netnod outcome

The exact reviewed v1 run used the
[archived Netnod authority manifest](../adr/evidence/0092-source-authority-v1.json)
and produced:

- recorded image-admission digest
  `2de1fa43994a3918b956ccc749da834ea0636f1983bf33207b0745b8bd3f9c12`;
- source image
  `sha256:e84be93c4e5d87a62eedba7c90be0fe1efe456c7fd1ffadcca61180772fc2114`
  and supervisor image
  `sha256:e1c70f736bc6ba33db5c62d7d5ac79ef7369f2a2621577d058b3631a97d417af`;
- contract `phase6c-live-trusted-time-qualification-inspection-v4`, embedded
  qualification SHA-256
  `d65a1270b91865ef674af5ea91d23daa0872c392af6b6aa05de3708056c919ac`,
  and retained artifact-file SHA-256
  `d1a36e8e96dd14a2552d5f911a16062122cb8fa2b5b55aca42bafa4fe104b2e7`;
- five current-epoch evaluations over an accepted 80.104-second span and
  fixed-cadence gaps, with exact current-process binding and fresh terminal
  evidence, but zero recorded samples and five `source_unavailable` outcomes;
  and
- `status=not_qualified`, terminal `health=blocked`,
  `reason=source_unavailable`, and every authority flag false.

The v1 image-admission digest and image IDs remain part of the reviewed record,
but the old canonical admission bytes predated content-addressed retention and
no repository file is claimed for that digest. The historical qualification
artifact remains retained at
[`trusted-time-qualification-d65a1270...19ac.json`](../../artifacts/trusted-time/trusted-time-qualification-d65a1270b91865ef674af5ea91d23daa0872c392af6b6aa05de3708056c919ac.json).

Direct Chrony inspection showed valid NTS authentication for both providers,
Cloudflare selected (`*`), and Netnod uppercase `D`: selectable, but excluded
from combining under Chrony's relative `combinelimit` rule. Uppercase `D` is
not the lowercase `d` absolute `maxdistance` rejection, and the observed peer
round-trip delay is not itself root distance. The exact adapter requires one
selected and one combined source, so it correctly produced no sample.

The supervisor was stopped before Chrony, both containers and the project
network were removed, the runtime secret staging directory was empty, and the
two named volumes were retained. Do not retry that authority automatically.
ADR 0093 implements a separate System76 Virginia v2 authority while preserving
the selected-plus-combined rule and 100-millisecond posture; it does not alter
this retained outcome.

## Retained 2026-08-01 System76 Virginia v5 qualification

The implemented v2 authority replaces Netnod with
`virginia.time.system76.com` while retaining `time.cloudflare.com`. Both use
NTS-KE TCP 4460 and negotiate NTP UDP 123. The exact implementation preserves
exactly two required sources, one selected (`*`) plus one combined (`+`), the
unchanged 100-millisecond uncertainty cap, and no unauthenticated, pool,
single-provider, retry, or selection-policy fallback.

The exact retained implementation and admission evidence is:

- current
  [v2 source-authority manifest](../../infra/trusted-time/source-authority.json)
  SHA-256
  `9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c`,
  Chrony-config SHA-256
  `5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23`,
  and authority-registry SHA-256
  `8e7a822503c5f73359cc18ee62dee4f56fb3e67f10b725374f8ef24c94344e9e`;
- reviewed source revision SHA-256
  `db81102def51115d85e9584ff8539aae1eede787939d0268e552dba40e8953b4`;
- immutable source image
  `sha256:8d704f59e4b627e38035b8056f9a63037e610f635cac12a8bf76ec4eff3422f3`
  and supervisor image
  `sha256:ca86611fc6177ec50d80ef0f4ed280bef93865d954c8aee0dceac403cf079d0c`;
  and
- admitted, content-addressed
  [`image-admission-b4519a60...e76e.json`](../../artifacts/trusted-time/image-admission-b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e.json),
  whose semantic and artifact-file SHA-256 are both
  `b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e`.

The retained inspector-v5 result is
[`trusted-time-qualification-1eb6c939...728c.json`](../../artifacts/trusted-time/trusted-time-qualification-1eb6c9396d9c82a76a1b57ba0b3266b4a420905e3f29e33613693087f23a728c.json):

- contract `phase6c-live-trusted-time-qualification-inspection-v5`,
  qualification SHA-256
  `1eb6c9396d9c82a76a1b57ba0b3266b4a420905e3f29e33613693087f23a728c`,
  and artifact-file SHA-256
  `0d0575adc139cc0ec2516d3d5011727986d17e0f856ca810da3bbe84ce0cdec2`;
- epoch sequence 8, with eight current-epoch evaluations, seven recorded
  samples, one `source_unavailable` outcome, an exact 140,064,973,522-nanosecond
  span, and qualified cadence;
- terminal evidence fresh and bound to the current process, with
  `health=healthy`, `reason=within_limit`, `hard_failure_latched=false`, and
  `clock_recovery_qualified=true`;
- observed uncertainty from `11.0340560000` through `16.0458345000`
  milliseconds, below the unchanged 100-millisecond cap; and
- `status=qualified`, with readiness, operational-control, new-exposure,
  alert-delivery, automatic-rearm, paper-trading, live-trading, and
  external-head-anchor authority all false.

One evaluation retained an intermittent System76 uppercase `D` state and
`source_unavailable`; the following seven evaluations recorded the required
selected-plus-combined samples and the terminal state qualified recovery.
Uppercase `D` means the source was selectable but excluded from combining at
that observation. This point-in-time recovery and qualification does not prove
continuous endpoint availability.

System76 publishes no SLA, upstream ensemble, redundancy commitment, or leap-
smear policy for this endpoint. Qualification cannot establish those
properties or a leap-event guarantee and does not elevate the topology beyond
evidence-only use. Preserve all Netnod database predecessors; only the fresh v2
epoch satisfied this v5 window.

The supervisor was stopped before the source. Both containers and the project
network were removed, the runtime secret staging directory was empty, and both
named volumes were retained.

## Failure handling

- Missing/extra sources, a single-source result, authentication failure,
  abnormal leap state, stale reference, malformed output, uncertainty above
  100 milliseconds, deadline expiry, or identity mismatch must fail closed and
  must not produce a successful sample. Do not add a fallback or retry.
- Point offset plus uncertainty from 250 through 1,000 milliseconds is warning
  evidence. Above 1,000 milliseconds is blocked and latches hard-failure
  evidence. Later recovery evidence never automatically clears the latch.
- A gap greater than 30 seconds blocks on the next evaluation. The scheduler
  skips missed catch-up ticks rather than compressing multiple probes into one
  instant.
- A fatal repository, clock, wait, or dependency failure terminates the
  supervisor. A trusted-head signature, fork, rollback, identity,
  configuration, persistence, or unclassified provider failure has the same
  result. The Compose profile does not restart it automatically.
- A positively classified anchor-provider outage retries only on the worker's
  20-second retry grid and never delays a local probe. The typed authenticated
  local-head compare-and-swap advance may also retry. Do not classify any
  other exception as transient. Anchor evidence is stale at 360 seconds or
  greater even while local probes continue.
- Supervisor death has no deployed independent watchdog. Evidence simply stops
  advancing; the external bucket does not observe or alert on that absence.
  The dormant pure Phase 6E state contract has no runtime or provider adapter.
  Staleness or the local cadence gap is recognized only by a later observation.
  End the directly observed window, record the failure, and do not infer an
  alert or control transition.
- Chrony uses `-x` and cannot repair host time. Correct the host/network cause
  outside this topology, then begin a newly approved process epoch. Do not
  rotate the fixed host ID or weaken source admission.

Do not use a healthy chain as a readiness bit or manually mutate operational
control. Exact-head-bound manual re-arm, alerting, and exposure gates are not
composed by this profile.

## Shutdown and evidence record

Stop the supervisor first, then the source:

```console
make trusted-time-stop
docker compose \
  --env-file infra/compose/trusted-time.defaults.env \
  --file infra/compose/trusted-time.compose.yaml \
  down
docker container ls --all \
  --filter label=com.docker.compose.project=autoquanttrader-trusted-time \
  --format '{{.ID}}'
```

For an enrolled future deployment, the supervisor first requests one
`clean_stop` checkpoint and requires exact remote readback plus its durable
receipt within the bounded worker shutdown. A transient provider failure does
not count as a clean stop. If `clean_shutdown_completed` is false, record the
stop as unconfirmed and do not infer freshness, recovery, or authority from the
last periodic checkpoint.

Do not use `down --volumes`; preserve the named Chrony state and the durable
runtime-Supabase evidence and every external signed object until the review
decides retention. Shutdown does not clear a hard-failure latch, prove
recovery, or authorize resume. The final
`docker container ls --all` command must print no container ID. Record that empty
result as the clean-stop observation; if a container remains, inspect and stop
that fixed project explicitly before ending direct supervision.

For qualification, retain the commit, immutable image IDs, manifest/config
digests, migration revision and empty-before/after counts, rendered security
and resource settings, sanitized two-source authentication/admission evidence,
probe timing and persistence evidence, injected source/deadline/process-failure
results, the inspector's canonical qualified or not-qualified artifact, and
the clean-stop result. For a future enrolled anchor, additionally retain the
sanitized project/bucket/policy/principal admission, nonsecret authority and
public-key digests, full startup/on-demand audit result, exact current
intent/receipt/object digests, staleness state, and confirmed anchor clean stop.
Mark Docker build, live source qualification, migration application, anchor
provisioning/enrollment, or drills `UNRUN` unless the corresponding retained
evidence exists.

Do not downgrade migration 0035 or 0036 as operational recovery. Migration
0035 refuses nonempty trusted-time history; migration 0036's downgrade refuses
nonempty anchor evidence. Preserve evidence and use an approved forward fix.
