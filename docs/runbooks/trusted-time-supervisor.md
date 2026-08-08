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
on 2026-08-01 with zero anchor intents and receipts. On 2026-08-04, approved
separate-project provisioning SQL SHA-256
`68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
committed; postflight proved the exact six-policy no-reader catalog and
dedicated Auth writer. On 2026-08-05, the dedicated writer password was rotated
and verified by a fresh Auth sign-in, and the owner-only runtime artifacts were
generated and decoder-validated. The first behavioral proof retained one
canonical object but failed closed at authenticated read; its policy-recovery
probe passed and the approved atomic upgrade committed with exact-catalog
postflight. The approved same-object resume then passed without a fresh insert,
and left the final object and namespace unchanged. Fresh parse-only Compose and
historical immutable-image admissions passed without granting authority or new
exposure. A later secure-launch attempt did not admit and retained no launch
receipt; secure-launcher runtime admission is `ATTEMPTED_NOT_ADMITTED`, while
first external enrollment remains `UNRUN`. Neither migration nor either
inspected window grants readiness or any trading authority.

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

## Implemented Phase 6D contract; proof complete, admission and enrollment incomplete

The Phase 6D code and runtime-database schema are implemented. Separate anchor
project `pgplscpqsvyraleyaphm` is Healthy on Supabase's Free plan with its Data
API disabled. Owner-only retained dashboard evidence records its exact private
`aqt-trusted-time-anchors-v1` bucket, 4,096-byte size limit, and sole
`application/json` MIME allowance. On 2026-08-04, approved provisioning SQL
SHA-256
`68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
committed. Read-only postflight at `2026-08-04T05:35:35Z` proved the exact whole
catalog of six policies, the dedicated writer, and no reader principal or
policy. On 2026-08-05, the dedicated writer password was rotated through the
Supabase Auth Admin boundary and verified by a fresh password sign-in for the
exact retained UUID and email. The offline generator then exclusively created
the raw signing key, Auth secret, and nonsecret authority outside the repository;
its secret-free receipt-file SHA-256 is
`c52cb3eccfefed713822fe797ac5f2f93c33565b60b41940faa93b2bb30bc264`,
the authority SHA-256 is
`9747c97be9cfabf51e524eef66120e8c7ec860be18e064416b17aa197eeb8f7c`,
and the signing-public-key SHA-256 is
`c86fec8a97a5630fb258e82b461336cc5ac053f7b2866a5694b5d571d0c92be7`.
All source and evidence files are owner-only mode `0600`; the runtime decoders
accepted their exact binding. Behavioral proof
`0396c9fe-0a8f-4b17-8c71-faa8a8033bb0` authenticated, inserted one canonical
object with no-overwrite semantics, and listed it, then failed closed at
authenticated read with a provider-masked `NoSuchKey`. Its owner-only canonical
failure evidence has SHA-256
`530a6ea5075ec787c16bdcbc1eb3a52e2900661e036e35ee24bb371c32f6d536`.
After the exact policy correction, an approved same-object resume on 2026-08-05
admitted that evidence, listed and read the exact retained object, performed no
fresh canonical insert, and completed the denial matrix. The overwrite, upsert,
update, delete, noncanonical-namespace insert, real-control-bucket insert,
anonymous insert/list/read, and public-read probes were denied; the final object
and namespace were unchanged. The owner-only pass-file SHA-256 is
`85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
and its internal `evidence_sha256` is
`5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`.
Fresh parse-only Compose and historical immutable-image admissions passed and
are retained. Secure-launcher runtime admission is
`ATTEMPTED_NOT_ADMITTED`, enrollment remains `UNRUN`, `allow_enrollment`
remains false, and no first enrollment has been approved or performed. Do not
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
sentinels with fresh protected staging paths after parsing one dedicated
current-user-owned, owner-only launch environment file exactly once. That file
must contain exactly `AQT_DATABASE_URL` and the three source-path assignments;
missing, duplicate, valueless, malformed, or additional assignments are fatal.
Its path must be absolute and canonical with no symlinked parent, and the file
must be a stable, current-user-owned, single-link regular file in exact mode
`0600`; descriptor metadata is compared before and after its bounded read.
Never pass the general repository `.env` or a file containing application,
broker, telemetry, or unrelated credentials; the launcher rejects basename
`.env` before opening it. The three source files must be absolute,
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
is now:

1. preserve the retained passing rollback-only policy-capability probe and
   applied exact-catalog v1-to-v2 upgrade evidence, plus the passing same-object
   no-insert behavioral-proof evidence;
2. create and review a new secretless content-addressed image admission from
   the exact merged revision containing the approval-binding hardening and
   bounded runtime diagnostic, obtain fresh approval for its
   revision/artifact/image tuple, then complete and retain local secure-launcher
   runtime admission without rebuilding;
3. separately obtain approval for and retain the first enrollment evidence;
4. only then implement a sealed provider-terminal issuer that authenticates a
   complete new suffix, binds two stable namespace passes to their exact
   digest/count/terminal identity, proves no higher sequence exists, and
   captures its own independent monotonic instant; and
5. only after that issuer is reviewed may a separate runtime apply the
   360-second stale threshold, with equality stale and every stale result
   unavailable, and qualify later consumers.

Until those steps occur, the current operational instruction remains direct
observation: a stopped supervisor is not independently detected or alerted.

## Qualification prerequisites

Before any new approved qualification window:

1. Require a clean exact merged commit and record its 40-character lowercase
   revision. Reject staged, unstaged, and nonignored untracked paths, plus every
   `assume-unchanged` or `skip-worktree` index entry. Confirm the exact reviewed
   path set, regular-file modes, and bytes match HEAD, including non-exempt
   ignored or info-excluded additions under reviewed source directories.
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
and sole `application/json` MIME allowance. Steps 1-5 below are complete and
retained; step 6 also completed after the reviewed policy recovery and same-
object resume, and step 7 is pending. Partial or complete provisioning does not
approve enrollment.

1. **Complete.** The distinct anchor project and exact primary bucket have
   retained dashboard evidence. Continue to record only
   identity digests and nonsecret project refs in reviewed evidence. Never
   insert or update `storage.buckets` directly.
2. **Complete.** Dedicated Supabase Auth writer
   `30876d87-2b57-4fb0-9488-20db3781ec04` is retained; no reader was admitted.
   Its password was rotated and verified by a fresh Auth sign-in on 2026-08-05;
   sanitized owner-only rotation evidence has SHA-256
   `e5d24ece7d09135c03888fea60a866b5fea867e46a35d042fde3e84f45e7ab95`.
   Do not supply the service-role key to the runtime.
3. **Complete.** `scripts/provision_trusted_time_anchor_project.py` validated
   the three distinct project refs, exact project URL, publishable key, and
   principal UUIDs and rendered deterministic
   `aqt-trusted-time-supabase-anchor-project-v1` SQL. Approved SHA-256
   `68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
   committed on 2026-08-04; postflight at `2026-08-04T05:35:35Z` proved the
   exact six-policy no-reader catalog. The transaction found the exact
   pre-created bucket. Its catalog gate examines the entire policy set on
   `storage.objects`: preflight accepts only no policies or the complete exact
   expected set, and postflight requires the entire set to be exactly the
   expected `aqt_tt_anchor_v1_*` policies. Fresh mode creates those final names;
   both fresh and existing modes create each equivalent audit policy in a
   rollback-only PL/pgSQL subtransaction, compare raw `pg_policy` trees, and
   catch only a private rollback sentinel before postflight. Real definition
   drift is raised outside that handler, and a transaction-scoped relation lock
   excludes concurrent policy DDL. The transaction must contain no policy rename
   or removal DDL against the provider-owned table. Any unrelated policy is
   drift. Exact apply and postflight evidence is retained. This deployed v1
   catalog omitted legacy metadata operation `object.get_authenticated_info`
   from both the writer SELECT policy and restrictive SELECT guard. The applied
   v2 contract corrects exactly those policies as documented in step 6.
4. **Complete.** Independent owner-only evidence retains the real private
   control bucket `aqt-trusted-time-anchor-proof-other-v1` in this same project.
   It is distinct from `aqt-trusted-time-anchors-v1` and receives no writer
   policy. This bucket exists only to prove cross-bucket denial.
5. **Complete.** On 2026-08-05,
   `scripts/generate_trusted_time_anchor_artifacts.py` exclusively created one
   raw 32-byte Ed25519 private key, one exact runtime-compatible Auth-secret
   JSON, and one nonsecret authority JSON at absolute, distinct owner-only
   targets outside Supabase and outside the repository. Runtime decoders
   revalidated all three, including the private/public signing-key match, exact
   writer binding, source/deployment identities, and bound publishable-key
   digest. The secret-free receipt-file SHA-256 is
   `c52cb3eccfefed713822fe797ac5f2f93c33565b60b41940faa93b2bb30bc264`;
   the deployment-identity SHA-256 is
   `e1290de2b5b340dee07f327af42f18b6bba0ccba0ea003be37783abc7b4ae892`.
   The result retains `allow_enrollment=false` and enrollment `UNRUN`. Never
   place the password, Auth secret, or signing key in reviewed evidence.
6. **Complete after approved recovery.** The first execution of
   `scripts/prove_trusted_time_anchor_storage.py` used proof ID
   `0396c9fe-0a8f-4b17-8c71-faa8a8033bb0`. Exact writer authentication, the
   no-overwrite canonical insert, and authenticated list passed. Authenticated
   read then returned an outer-400/inner-404 `NoSuchKey`, so the command stopped
   with `proof_canonical_object_changed`, `UNKNOWN_REVIEW_REQUIRED`, and no
   denial-matrix completion. Preserve the retained object and owner-only
   canonical failure evidence SHA-256
   `530a6ea5075ec787c16bdcbc1eb3a52e2900661e036e35ee24bb371c32f6d536`;
   never rerun in fresh-insert mode for that proof ID.

   The exact owner-only rollback-only artifact
   `phase6d-anchor-read-policy-drop-capability-probe.sql`, SHA-256
   `73f7db8b16033848cbc9790310bd7a6d4e3c4537d6a694cac9fdf368d12eea18`,
   passed under role `postgres` on 2026-08-05 and reached its terminal rollback.
   It admitted and parse-tree-proved only the exact deployed six-policy v1 catalog,
   attempts DROP only for `aqt_tt_anchor_v1_guard_select` and
   `aqt_tt_anchor_v1_writer_select`, and always ends in `ROLLBACK`. Retain a
   read-only postflight regardless of outcome. Owner-only pass evidence SHA-256
   is `706ddc3a7a9e9f656e42b037b7e92e0dd2acd90cdd68a97d2fa4ef653bd29e81`.
   The retained postflight SQL SHA-256
   `f9dff727a72661a3deafa84a7d711db73b4499427bb003b0687c58b8c96078ce`
   proved exact equality with the baseline bucket and complete policy catalogs;
   its primary object count remained one and enrollment remained `UNRUN`.

   The capability probe satisfied its gate. The separately approved exact
   owner-only atomic artifact
   `phase6d-anchor-read-policy-v1-to-v2-upgrade.sql`, SHA-256
   `b35de9ae59438481a9f4e26bb9e18a6c3fd37eca2648f7f0ded3e6c87e0fee55`,
   committed under role `postgres` on 2026-08-05. It locks and proves the exact
   v1 catalog, atomically replaces only those two
   SELECT policies to add `object.get_authenticated_info`, proves all six v2
   definitions plus exact whole-catalog equality, and then commits. It performs
   no `storage.*` row DML. Owner-only applied evidence SHA-256 is
   `57a4ce0914d36b179adce7f40afda99bb7bd5d859a2a9f33cb2d40984bca62e3`.
   The locked read-only postflight proves the complete v2 catalog, exact
   two-policy delta, one retained object, and enrollment `UNRUN`.

   On 2026-08-05, the approved same-object resume used exact proof ID
   `0396c9fe-0a8f-4b17-8c71-faa8a8033bb0` and the retained canonical failure
   evidence. It performed no fresh canonical insert, admitted the retained
   evidence, listed and read the exact existing object, and denied the
   overwrite, upsert, update, delete, noncanonical-namespace insert,
   real-control-bucket insert, anonymous insert/list/read, and public-read
   probes. The final object and namespace were unchanged. The owner-only
   pass-file SHA-256 is
   `85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
   and its internal `evidence_sha256` is
   `5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`.
   Preserve only sanitized results, never tokens, passwords, or response
   bodies. Enrollment stayed `UNRUN` with `allow_enrollment=false` throughout.
7. **In progress.** Preserve the passing parse-only Compose and historical
   immutable-image evidence described below. Do not reuse either drifted tuple.
   Build and review a new secretless content-addressed admission from the exact
   merged revision containing the approval-binding hardening and bounded runtime
   diagnostic, obtain fresh tuple approval, then use the no-build admission
   launcher to stage, admit, and retire the exact database, authority, Auth, and
   signing-key mounts without exposing their contents. Confirm the production
   composition still fixes
   `allow_enrollment=False` with no environment override, then stop and request
   separate owner approval for any reviewed one-time enrollment enablement and
   operation.

Administrator/provider access can bypass these writer policies. Record that
the result is same-provider and potentially same-admin evidence, not WORM or
independent custody.

## Secretless review and networked image build

Use the checked-in credential-free sentinel Compose defaults file so Docker
Compose does not load an owner credential file implicitly. The file is not
empty: it contains only the six reviewed image/path sentinel assignments.
Image construction may fetch pinned base/package/source inputs and therefore
is not an offline operation:

```console
make trusted-time-compose-check
make trusted-time-images
```

These targets use a fresh locked, offline uv environment rather than the
repository `.venv`, then require isolated Python, disabled bytecode writes, a
`/dev/null` bytecode-cache prefix, and canonical first-party `.py` origins.
They do not independently authenticate the uv executable, base interpreter, or
global uv content cache. The separately approved 2026-08-05 operator-local
cache prewarm installed the exact lock graph, and the isolated runtime reported
`cryptography==49.0.0`. A clean host without those cache objects fails closed
offline. Do not weaken these flags or fall back to `.venv`; prewarm only the
exact locked dependency cache under separate approval.

The first command validates the rendered service allowlist, config/secret
mounts, resources, privileges, and absence of inbound ports. It requires the
database secret, Phase 6D authority config, Auth secret, and signing-key source
variables to use the checked-in parse-only `/dev/null` sentinels. The second
builds both targets and verifies their immutable metadata, exact Chrony/config
bytes, the exact root-owned CA bytes, NTS-enabled version, secretless
fail-closed result, and lack of embedded credentials. Before invoking either
direct Docker build it renders and admits that exact sentinel model from the
Compose YAML stored at HEAD. It writes only if two status observations are
clean, every index flag is ordinary, and the exact reviewed path set, modes,
and stable bytes match bounded Git object reads. It then atomically writes the
mode-`0600` canonical
`artifacts/trusted-time/image-admission.json` and an identical owner-only
`image-admission-<artifact-sha256>.json` content-addressed artifact. Approval
and admission launch use the content-addressed file; the canonical name is not
an approval pin. The artifact binds the exact source and supervisor image IDs
to the checked-in Dockerfile, Compose/config/authority, pinned CA, migration
0036 bytes, schema head `0036_phase6_time_anchors`, catalog relations
`phase6_trusted_time_head_anchor_intents` and
`phase6_trusted_time_head_anchor_receipts`, `Makefile`, the
`scripts/bounded_subprocess.py` runner, `scripts/credential_env.py` loader,
dependency lock, and reviewed supervisor/package source digest under contract
`phase6d-trusted-time-image-admission-v2`. The v2 artifact and verifier JSON
also bind and report the exact captured 40-character Git revision used for the
sealed build; copy that value into the approval record rather than sampling
`HEAD` afterward. They also report a nonsecret canonical `boot_session_id`
(`linux:<kernel-boot-id>` or `darwin:<kern.bootsessionuuid>`). The loader
requires exact current-session equality before applying the 15-minute
monotonic freshness window; an unreadable, unsupported, or changed session
fails closed.
Docker Desktop must be running locally; a Compose parse alone is not build or
runtime evidence.

The image builder never gives Docker the live checkout. It assembles one
bounded deterministic tar from the exact allowlisted HEAD blobs, verifies the
Dockerfile-specific deny-by-default `.dockerignore`, and sends the same tar on
stdin to both direct target builds under one exact minimal Docker environment.
It requires the content-addressed Dockerfile frontend
`docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`
and rejects a mutable or different directive. Each quiet build must return one
exact immutable `sha256:` ID. Verification and
the admission artifact use those captured IDs, never a later resolution of the
mutable `phase6d-v1` tags. Compose validation receives the exact HEAD YAML on
stdin with `--env-file /dev/null` and a fixed project directory. Do not replace
either path with `docker compose build` or a live-checkout context.

All Git, Docker, Compose, and macOS boot-identity subprocess pipes use
command-specific input/output caps and absolute deadlines. Overflow, timeout,
or malformed decoding kills and reaps the isolated process group and fails
closed; do not replace the bounded runner with `capture_output=True`.

Keep both canonical and content-addressed artifacts below the repository's
ignored owner-only `artifacts` root. Relative, noncanonical, root-equal, or
outside-root paths fail before Git or Docker activity; unsafe existing parent
or file metadata fails later at the descriptor boundary and still prevents an
artifact from being admitted.

Treat these commands as unperformed for each new exact merged 40-character
lowercase revision until they are run on that revision. Retain the
content-addressed admission artifact and its two immutable image IDs, not only
the canonical name or mutable `phase6d-v1` tags. Equivalent Docker builds are
not required to produce the same image ID; every rebuild creates a new tuple
that requires fresh review and approval. Never compare a new build to a prior
ID or admit a running arbitrary ID. Verify from image metadata and the rendered
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

The pre-admission-hardening Phase 6D launcher/Compose/image baseline passed 103
focused tests and the actual Docker Compose verifier. That historical result
does not cover the later typed-terminal observer, approval tuple, or v2 receipt
path. The approval-binding hardening is merged at
`2fcd3cdcf343bf4ef0630b2923190df7556c630d`; its bounded V5 diagnostic and
isolated Compose verifier pass locally. Build and runtime evidence must still be
produced from the exact final merged revision containing those changes.

On 2026-08-05, an earlier parse-only Compose verifier admitted a reviewed model
with zero inbound ports and no authority. Historical immutable-image artifact
SHA-256
`10e7feea32ed2ad093e59f7075e60147af5fa4835986e7772262a44f64a81b07`
binds reviewed-input SHA-256
`05f2fa1a3c24fb7e7e1a5722f8117f652541dd14947d6dddd90c3dfa4fdde09a`,
source image
`sha256:c3d81b9e1fa19b1d8131c99554da2c8ee8e6b928f27444293e82b237a24371a0`,
and supervisor image
`sha256:06944ec20029fca39db5e8069f3cb3d1397333304cd6ca70343bf2c6fff312ba`.
It records `authority_granted=false` and `new_exposure_authorized=false`.

Two later image-admission builds from merged revision
`377cb9bcc80dfeafde680097e483d2f3195f615b` and the same reviewed-input
SHA-256 `d691523d732e29c59773411e145c6462e94505b1d5e7e92e523a152b64ac9a10`
retained different immutable pairs:

- artifact `b78bda0469077672beacbb746d0278db8b4f84dc5aead65d155c61b98ba4d0d7`
  binds source image
  `sha256:97e8763181685663fb545bb926d3a213ffac4add3df53672ff92f9e615938810`
  and supervisor image
  `sha256:214a627e9bc7bac9306be186bbc6f617434f337be8611edc138b067f45c3bbda`;
  and
- artifact `a119b19699c4ce97a13c207d47a9c80c796194d71c99ace97489800838d1dabe`
  binds source image
  `sha256:052439221d37672143eac652592f318c412b4b2f2948e7d20df1f84af0d7a8b9`
  and supervisor image
  `sha256:fa22b4b58474204f25e10281e224bdb5fdc184cce52ccc730948685a3fad04db`.

At the 2026-08-07 pre-build review, these three were the retained canonical or
content-addressed `image-admission*.json` artifacts. They use a superseded v1
image-admission schema, omit the captured `git_revision`, and are rejected by
the current v2 loader.
They are historical evidence of permitted build-identity drift, not an approval
for the next exact merged revision. The following secure-launch attempt did not
admit and retained no v2 receipt, so secure-launch status is
`ATTEMPTED_NOT_ADMITTED`; first enrollment remains `UNRUN`. The approval-binding
hardening is merged in revision
`2fcd3cdcf343bf4ef0630b2923190df7556c630d`. Do not retry until new images and a
new content-addressed v2 admission are created from the exact merged revision
containing the bounded runtime diagnostic, and the owner grants fresh approval
for the new tuple.

Any mismatch stops qualification. Do not retag or patch a running container to
make it pass.

Plan and complete CA rotation before `2031-04-26T10:56:53Z`. Treat rotation as
a new reviewed authority/image pair and prove one real `verify-full`
connection to the intended Supabase Session-pooler hostname before use.

## Bounded read-only runtime diagnostic

Use the V5 diagnostic before building or launching a fresh tuple. It consumes
the same dedicated exact-four launch environment as the secure launcher; the
file must satisfy the canonical owner-only mode-`0600` contract described
below. The general repository `.env` is forbidden. Run:

```console
make trusted-time-runtime-diagnostic \
  TRUSTED_TIME_LAUNCH_ENV_FILE=/absolute/path/to/trusted-time-launch.env
```

The command creates a fresh locked offline isolated Python runtime. It opens the
exact-four file once, makes read-only database transactions, authenticates the
configured Supabase user, and performs two bounded one-item lists of only the
exact deployment prefix. It never registers an epoch, writes database rows,
uploads or changes a Storage object, enrolls the prefix, starts Compose, or
grants operational authority. Supabase password sign-in may update provider-side
Auth session or audit metadata even though application data remains read-only.

Standard output is exactly one canonical ASCII JSON object under contract
`phase6d-bounded-read-only-runtime-diagnostic-v5`. Failure output contains only
a fixed allowlisted `outcome_code`, `status=failed`, the contract version, and
false authority flags. The fixed taxonomy covers launch/database/local-history
gates; provider identity, authentication, availability, and Storage-list gates;
and password-token request-target, encoding, response-bound, envelope, and
session-schema guards. It never renders credentials, DSNs, paths, URLs, IDs,
object names, headers, byte counts, response bodies, or exception text. A pass
adds bounded aggregate counts and fixed booleans only; it does not approve image
admission, enrollment, readiness, re-arm, paper trading, or live trading.

On 2026-08-07, the owner-approved V5 diagnostic returned
`outcome_code=diagnostic_passed`. It verified the current database schema and
integrity, an authenticated startup snapshot, zero local anchor intents and
receipts, the exact provider identity, and two stable empty-prefix observations.
The bounded aggregates were nine epochs, one evaluation in the latest epoch,
and 112 local transitions. That stdout was operator-observed and was not
retained as an image-admission or secure-launch receipt; every authority flag
remained false.

## Approval-blocked supervised start

The separate-project Storage behavioral proof is complete, including the
passing no-insert same-object recovery. This section remains approval-blocked
because local secure-launcher runtime admission is
`ATTEMPTED_NOT_ADMITTED`, first enrollment remains `UNRUN`, production
composition fixes `allow_enrollment=False`, and no first enrollment has been
approved or performed. Owner-only runtime artifacts and the passing Storage
proof do not approve enrollment. A start must fail closed when the exact
authority/secrets are absent or the remote prefix is unenrolled. Do not run
`make trusted-time-start` as a provisioning experiment and do not weaken that
behavior to repeat the earlier source-only window.

Image preparation and admission launch are deliberately separate. Run
`make trusted-time-images` secretlessly on the clean exact merged revision
before requesting approval. Review its content-addressed artifact, exact
40-character lowercase merged Git revision, artifact SHA-256, and two immutable
`sha256:` image IDs as one tuple. A repeated build is a new approval boundary
even when the reviewed inputs are unchanged.

Admission mode never builds or rewrites an image-admission artifact. Before it
opens the launch environment, it requires the local `HEAD` to equal the approved
revision, applies the exact Git status/index/HEAD-byte gate, derives and loads
the content-addressed `image-admission-<artifact-sha256>.json`, validates its
canonical owner-only bytes, freshness and current reviewed-input binding,
requires both artifact image IDs to equal the approved IDs, fully verifies
exactly those installed images, fences the local Docker daemon, renders the
placeholder Compose model from the approved HEAD YAML, and repeats the
revision/artifact/identity gate. It then parses one dedicated
launch environment exactly once and rejects every name except
`AQT_DATABASE_URL` and the three absolute Phase 6D source-file variables. The
general repository `.env` is forbidden, and basename `.env` is rejected before
the file is opened. Immediately before Compose, it fences the daemon and
repeats the approved revision and content-addressed artifact gate again.
Every Compose `up`, `ps`, and `down` receives the same approved HEAD YAML on
stdin with implicit env-file loading disabled and a fixed project directory;
no live Compose/default file is reread. Compose uses `--no-build --pull never`
and the approved immutable IDs. Non-Compose Docker probes receive only the
finite minimal pass-through environment; only `LC_ALL`, not arbitrary `LC_*`
names, is locale-eligible. Alpaca, E\*TRADE, Sentry, and other application
credentials are neither accepted in the launch file nor forwarded. Runtime
Compose YAML is capped at 4,096 bytes so bounded observers cannot block while
writing stdin, and each Compose render has a 15-second timeout.

All image-verification `docker run` probes also use `--pull=never`. After the
expected terminal is observed and topology teardown is verified, the launcher
rechecks the clean approved revision and content-addressed artifact once more;
failure at that final gate retains no v2 receipt.

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
exited process cannot re-read or restart from a retired mount. Every failure
path attempts exact current-input cleanup even if topology stop or teardown
proof fails; cleanup failure is fatal. Do not place any secret on a command
line or copy it into `trusted-time.defaults.env`.

After the secretless build and review, set the four nonsecret approved values
from one approval record and run the separately approval-gated admission-only
command:

```console
make trusted-time-admit-unenrolled \
  TRUSTED_TIME_LAUNCH_ENV_FILE=/absolute/path/to/trusted-time-launch.env \
  TRUSTED_TIME_APPROVED_GIT_REVISION="$APPROVED_GIT_REVISION" \
  TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256="$APPROVED_IMAGE_ADMISSION_SHA256" \
  TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID="$APPROVED_SOURCE_IMAGE_ID" \
  TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID="$APPROVED_SUPERVISOR_IMAGE_ID"
```

All four approval variables are required. The CLI validates their exact shapes
and correspondence to the current revision, content-addressed artifact, and
installed images; this value validation does not prove that the revision was
merged, prove who approved it, make the approval single-use, impose an approval
TTL, or prevent replay. Preserve the separate manual approval record as the
merge-provenance and approval evidence. A successful canonical
`phase6d-unenrolled-secure-launch-admission-v2` receipt binds the exact approved
revision, artifact SHA-256, source image ID, and supervisor image ID. Its UUIDv4
distinguishes attempts but is likewise not approval, freshness, or anti-replay
proof.

It first requires that the exact Compose project has no prior supervisor
container, before opening the owner environment file. It never enables
enrollment. The expected supervisor outcome is exit 2 with the exact typed
reason `head_anchor_remote_history_absent_enrollment_not_approved`; generic
`supervision_failed`, `configuration_rejected`, OOM, restart, replacement,
malformed output, timeout, or any other reason fails admission. The observer
uses only fixed Docker inspect/log/Compose commands, a full container ID, hard
stdout/stderr limits, and one absolute deadline per observation: at most 60
seconds on the normal post-validation path and two seconds in early-failure
race paths. Each bounded child reserves up to 250 milliseconds inside its
supplied lifecycle deadline to kill, wait for, and finally poll a failed
subprocess. It forwards only the minimal Docker client environment, never
application or broker variables.

The expected terminal outcome is not sufficient by itself. A successful
wrapper result is permitted only after the normal secure-launch topology,
mount, input-consumption, staged-input retirement, retired-mount, daemon, and
image checks have all passed, followed by verified topology removal and named-
volume preservation. Topology removal includes all Compose project containers
and the exact project network. Volume preservation compares stable creation,
mount, driver, option, label, and scope identity captured after successful
topology validation with the same two objects after teardown; matching names
alone are insufficient. Only then does the wrapper exit zero and retain
canonical owner-only contract `phase6d-unenrolled-secure-launch-admission-v2`
below `artifacts/trusted-time`, named by the SHA-256 of its exact bytes. The
receipt binds the approved revision/artifact/image tuple and has a per-attempt
UUIDv4 but no trusted timestamp; neither the tuple nor UUID is single-use,
freshness, or anti-replay evidence. It contains no container ID, filesystem
path, hostname, credential, provider body, enrollment permission, or trading
authority.

An expected terminal observed during Compose startup failure or the private
supervisor-identity-disappearance race before all secure-launch checks complete
is `secure_launch_incomplete`: the wrapper exits 2 and writes no admitted
receipt. Unrelated topology or mount failures retain configuration rejection.
Timeout, teardown failure, remaining containers, remaining project network,
missing or replaced named volumes, current-attempt staging residue, receipt-
publication failure, or canonical-output failure also override an otherwise
expected terminal. Canonical-output failure rolls back the just-published
receipt and fsyncs its removal. If unlink or removal durability cannot be
confirmed, fixed stderr reason `admission_retention_unconfirmed` requires
manual inspection of the artifact directory; the result remains non-admitted
with exit 2. Preserve the exact admitted receipt
and its file SHA-256 only after a zero exit. This command proves no enrollment;
stop and request separate owner approval before any first-enrollment change.

After retained separate-project provisioning evidence and a separately
approved, reviewed first enrollment, the normal post-enrollment start is:

```console
make trusted-time-start \
  TRUSTED_TIME_LAUNCH_ENV_FILE=/absolute/path/to/trusted-time-launch.env \
  TRUSTED_TIME_APPROVED_GIT_REVISION="$APPROVED_GIT_REVISION" \
  TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256="$APPROVED_IMAGE_ADMISSION_SHA256" \
  TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID="$APPROVED_SOURCE_IMAGE_ID" \
  TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID="$APPROVED_SUPERVISOR_IMAGE_ID"
```

The persistent path requires the same exact revision/artifact/image tuple and
never rebuilds. The first enrollment needs its own reviewed enablement because
production is hard-wired to deny it; the normal command above cannot create
sequence 1.

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
make trusted-time-inspect \
  TRUSTED_TIME_INSPECT_ENV_FILE=/absolute/path/to/trusted-time-inspect.env
```

The inspection environment must be a separate current-user-owned, owner-only
file containing exactly one assignment, `AQT_DATABASE_URL`. Do not reuse the
four-variable launch file or the general repository `.env`; basename `.env` is
rejected before opening. The inspector revalidates the exact Supabase
Session-pooler and pinned-CA contract, runs the full operational-schema and
trusted-time replay-integrity gates, and holds a read-only repeatable-read
snapshot for host
`local-paper-docker-primary-v1`.

Before inspecting any image or container, the inspector resolves the effective
Docker endpoint selected by `DOCKER_HOST`, `DOCKER_CONTEXT`, or the active
context. The endpoint must canonicalize to an existing local Unix socket owned
by root or the current user and must not be world-writable. TCP, SSH, HTTP, and
other remote endpoints are rejected before daemon contact. The inspector binds
the context, canonical socket endpoint, and Docker daemon ID in memory, then
requires that exact local-daemon identity immediately before and after its
container and clock rechecks. A daemon, context, or endpoint change fails the
inspection; none of those private daemon details enter the artifact.

Before reading the database secret, the inspector opens canonical
image-admission bytes and their identical content-addressed sibling through an
owner-only, mode-`0600`, regular, single-link, non-symlink file descriptor. It
rejects noncanonical bytes, duplicate or extra fields, stale host-monotonic
creation evidence (the artifact is valid for 15 minutes), a current
reviewed-input mismatch, a missing content-addressed copy, or a changed
artifact between identity fences. This alone does not prove which approved
launch tuple or v2 secure-launch receipt created the running topology; preserve
and compare those separate records operationally. It fully re-runs image
verification against only the two artifact-bound immutable IDs without
rebuilding. It then requires the two
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
- historically admitted under superseded image-admission schema v1,
  content-addressed
  [`image-admission-b4519a60...e76e.json`](../../artifacts/trusted-time/image-admission-b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e.json),
  whose semantic and artifact-file SHA-256 are both
  `b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e`;
  it omits `git_revision` and the current v2 loader rejects it.

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

No approval-bound frozen persistent-shutdown path is implemented yet.
`make trusted-time-stop` intentionally exits 2 and must not be replaced with a
live-checkout Compose command. Unenrolled admission mode performs and verifies
its own container/network teardown. Before the persistent-start gate is
reopened, implement and separately review a graceful shutdown that uses the
approved HEAD Compose bytes and tuple, requests the supervisor stop first,
waits for its bounded clean-stop result, then stops the source and verifies
topology removal without deleting named volumes.

The following read-only command may confirm that no project container remains
after launcher-managed admission teardown:

```console
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
