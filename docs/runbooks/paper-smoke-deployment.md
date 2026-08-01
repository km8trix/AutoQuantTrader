# Paper smoke deployment

This runbook prepares the amended ADR 0088 supervised local paper profile. It
does not authorize exposure, unattended operation, a transition to `RUNNING`,
or a durable strategy invocation. The current scope is exact-image packaging,
Supabase connectivity/schema, Sentry configuration, and offline verification
of the only approved artifact. The credential-aware checks run on the host and
do not execute a database/Sentry-bound container. If a later separately
reviewed profile authorizes a durable invocation, its only acceptable strategy
result is `NO_EXPOSURE` with an empty proposed-intent list.

A separate owner-operated account-enrollment command is documented below. It
is not part of the preflight, does not activate Phase 5, and must not be run
without its own approval for one authenticated read and durable raw-response
retention.

## Fixed topology

- one directly observed unbound image verification plus one host-side
  credential-aware preflight using the owner's local Mac CPU/RAM;
- one Supabase Free PostgreSQL project bound through `AQT_DATABASE_URL`;
- one historically enrolled Alpaca paper account whose exact nonsecret
  identity pins are reauthenticated read-only, and no live credentials;
- Sentry diagnostic OTLP trace configuration, without runtime exporter
  composition;
- no PagerDuty, Twilio, or external stale-heartbeat watchdog;
- no public operations API or browser dashboard; and
- configured non-authorizing `PAUSED` policy plus an aggregate read-only
  control-head safety scan, with no authenticated account-bound control
  observation and no re-arm authorized by this profile.

Hosted or unattended compute, PagerDuty, Twilio, paid Supabase capacity, and an
Alpaca data-plan upgrade are deferred. Because no external notification route
or independent watchdog is available, the checks may run only during an
operator-declared, directly observed window. Host sleep, reboot, network loss,
process exit, an unresponsive check, or loss of supervision ends the window.
Changing a provider, making an inbound service public, enabling unattended
execution, selecting another strategy, accepting live credentials, or changing
the control policy requires a new reviewed profile rather than an environment
override.

## Repository implementation status

The selected provider boundaries are implemented and tested locally:

- the production container pins its build bases by digest, runs as UID/GID
  10001, keeps the strategy artifact, manifest, and trader source root-owned
  without group/other write access, exposes no port, defaults to `paper`, and
  invokes only the one-shot admission command. The workflow resolves its exact
  inspected `sha256:` image ID and does not treat the local tag as immutable;
- CI builds that production target, inspects its metadata and runtime-input
  ownership, and requires the default process to exit `2` with every authority
  flag false while external sources remain unbound;
- the Sentry Cloud OTLP/HTTP trace-exporter factory validates a project DSN,
  derives the fixed trace endpoint and authentication header while redacting
  that header from representations and failures, pins the paper
  service/release/environment, and strips non-allowlisted span content;
- `scripts/bind_alpaca_paper_account.py` composes the existing Phase 4G
  authenticated account-read boundary as a directly supervised, one-shot
  enrollment command. It requires an independently obtained provider UUID pin,
  sends at most one fixed paper `GET /v2/account` with no retry, retains the
  exact response in Supabase before decoding, and can append only a secret-free
  short-lived account binding whose observed provider UUID matches the pin;
- `phase5-paper-account-enrollment-attestation-v1` authenticates the configured
  account's complete durable binding/source history and exact terminal identity
  in one repeatable-read snapshot, then emits only non-authorizing digest and
  sequence evidence;
- `pagerduty-events-v2-primary` implements bounded PagerDuty Events API v2
  primary delivery; and
- `twilio-messaging-service-sms-escalation` implements bounded Twilio
  Messaging Service SMS escalation with a restricted API key.

These are local components, not activation evidence. On 2026-07-29, the
operator supplied a Sentry DSN outside the repository and observed transport
acceptance for one sanitized synthetic trace. That was a non-durable setup
observation, not a checked-in or reproducible receipt, and queryable ingestion
has not been proven. The repository still lacks durable worker/exporter
composition and a durable strategy invocation. PagerDuty/Twilio routes,
recipients, worker/watchdog composition, external delivery probes, and
provider-independence drills are deliberately unavailable. They block
unattended or Phase 5 deployment readiness, but do not block a directly
supervised no-exposure preflight.

On 2026-07-31, the separately approved single-shot recovery established one
terminal binding at account-local binding sequence one. The original raw-only
attempt and both request/lease histories remain preserved. This dated result
proves historical identity only; its account-status window expired after at
most five seconds.

The v2 assessment and credential-aware local preflight consume the
owner-approved database/test/Sentry bindings plus, when configured, all four
nonsecret account identity pins. They validate distinct Supabase session/TLS
identities, the exact migrated schema, the inspected local image ID, Sentry
configuration, and artifact pins. They do not request, return, resolve, or use
Alpaca API credential variables, call Alpaca, create control state, or
authenticate an account-specific operational-control head. The shared dotenv
parser does parse the complete owner-only file before filtering selected
variables, so the preflight process remains inside that file's credential
boundary. ADR 0089 reauthenticates the exact historical terminal enrollment
but explicitly reports account status and binding freshness false. The
aggregate control scan still requires zero `RUNNING` heads. A successful result
is `smoke_preflight_ready`; it still reports external notifications unavailable
and Phase 5 activation false. Do not invent current account, control, provider,
route, recipient, or watchdog evidence to remove those blockers.

The durable strategy claim path has an additional intentional gate: its start
authorization requires an authenticated account-bound `RUNNING` control head.
The current preflight configures only a non-authorizing `PAUSED` policy. Its
account evidence is historical, while its control observation remains an
aggregate safety observation: either no heads or only non-running heads are
present. A successful local preflight cannot establish or lower durable state,
does not create a durable strategy result, and does not close Phase 5.

## Owner-controlled prerequisites

Before starting a smoke window:

1. Address the owner's untracked `.env` by an absolute path with no symlinked
   parent components. Confirm it is a current-user-owned mode-`0600` regular
   file no larger than 128 KiB with no duplicate assignments, that
   `AQT_DATABASE_URL` identifies the intended Supabase Free runtime database,
   and that `AQT_TEST_POSTGRES_URL` identifies a different database. Do not
   print either DSN.
2. Keep the four nonsecret paper-account identity pins in the owner-controlled
   environment. The current preflight consumes those pins only to authenticate
   the existing historical binding; it does not select, return, resolve, or use
   paper trading keys or the base URL, make a provider request, or prove current
   account status. SIP entitlement is not required for this preflight and must
   not be inferred. Never derive the trusted provider UUID pin from the same API
   response being qualified.
3. Restrict the existing Sentry project to the operator, enable MFA, confirm
   its project DSN/client key, and keep `AQT_SENTRY_DSN` only in the untracked
   local environment. The local exporter derives OTLP
   endpoint/authentication values at runtime; do not copy them into checked-in
   configuration. Do not enable request bodies, PII, local variables, or
   account/order payload capture.
4. Keep PagerDuty and Twilio routes deferred and unconsumed. Their environment
   variables, if present for unrelated local work, are ignored by this
   preflight and do not create a route or receipt. No external critical alert or
   fallback receipt is available in this profile; Sentry is not a substitute.
5. Keep the Mac connected to power and awake for the declared observation
   window. Run one check at a time and keep its terminal/process status visible
   to the operator. The database verifier enforces per-connect, pool, statement,
   and lock limits but has no whole-command timeout; stop an unresponsive check
   and record the evidence as unavailable. Do not leave the preflight
   unattended.

Hosted compute, paid database capacity, external paging, SMS enrollment, and a
stale-host watchdog are explicitly deferred owner actions.

## Secret and identity rules

- Secret values are configured only in the owner's untracked mode-`0600`
  `.env` or a stronger local secret store.
- Checked-in and durable configuration contains only nonsecret references,
  immutable versions, opaque deployment IDs, and SHA-256 digests.
- The runtime PostgreSQL DSN and destructive test DSN must identify different
  databases. A shared host or Supabase organization does not prove separation.
- Do not print or persist DSNs, Sentry client keys, PagerDuty routing keys,
  Twilio credentials, phone numbers, email addresses, or Alpaca credentials.
- Reject any `secret://live/...` reference or Alpaca live base URL.
- Treat `AQT_PAPER_ACCOUNT_ID`, `AQT_PAPER_PROVIDER_ACCOUNT_ID`,
  `AQT_PAPER_BROKER_SECRET_REF`, and
  `AQT_PAPER_BROKER_SECRET_VERSION` as nonsecret identity configuration. The
  provider account ID must be a canonical lowercase UUID obtained
  independently of the binding response. The secret reference must use the
  `secret://paper/...` namespace and must not contain credential material.

## Supervised smoke sequence

1. Require the full repository CI suite on the exact commit. Confirm
   `git status --short` is empty, record `git rev-parse HEAD`, and build the
   production image from that clean revision:

   ```console
   git status --short
   git rev-parse HEAD
   docker build \
     --target production \
     --file infra/docker/api.Dockerfile \
     --tag autoquanttrader-runtime:paper-preflight-local \
     .
   ```

   Any `git status --short` output stops the sequence.
2. Resolve and record the local image's exact `sha256:` ID. Use that exact ID,
   not the mutable tag, for every subsequent image check:

   ```console
   docker image inspect \
     --format '{{.Id}}' \
     autoquanttrader-runtime:paper-preflight-local
   ```

   Verify the exact image contains the ADR 0087 manifest and artifact digests.
3. Record a logical export before migration where the Supabase Free project and
   local network path support it. Do not claim a backup or restore objective
   without verified evidence.
4. Use only the purpose-built Phase 6 migration operator for the production
   transition from exact revision `0034_phase6_trusted_time` to exact revision
   `0035_phase6_time_uncertainty`. The owner environment must be an absolute,
   non-symlinked, current-user-owned mode-`0400` or mode-`0600` file containing
   distinct `AQT_DATABASE_URL` and `AQT_TEST_POSTGRES_URL` bindings. Create an
   absolute, non-symlinked, mode-`0700` evidence directory outside the
   repository; the operator creates each evidence file atomically at mode
   `0600` and refuses to overwrite it.

   Run the following sequence from the repository root, replacing every
   placeholder with the exact reviewed owner path. Do not export either DSN to
   the shell or pass it as a command argument:

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

   Require `check-bindings` to authenticate the pinned CA, exact migration
   bytes, Alembic edge, and bound source files. Require `test-postgres` to pass
   against only `AQT_TEST_POSTGRES_URL` with `runtime_target_untouched=true`.
   Require `preflight-runtime` to report `status=ready`; its canonical artifact
   must bind prior revision 0034, active TLS, the expected pre-0035 catalog,
   and zero rows in all three trusted-time tables. The artifact expires after
   15 minutes. Obtain explicit owner approval after reviewing that artifact and
   immediately before `apply-runtime`.

   `apply-runtime` revalidates the unchanged owner file, source bindings, live
   catalog, empty histories, and preflight artifact under an advisory lock. It
   can execute only migration 0035, then requires exact revision 0035, the new
   uncertainty column and policy constraints, zero trusted-time rows, and the
   full operational-schema gate before writing the postflight artifact. Stop
   on any nonzero exit. If output says `migration_committed=true`, do not retry
   merely because later verification or artifact publication failed; preserve
   the evidence and review the runtime catalog first.

   Never substitute raw `alembic current`, `alembic upgrade head`, or bare
   `make migrate` in this production sequence, and never direct the migration
   step at `AQT_TEST_POSTGRES_URL`. These commands are instructions, not
   evidence. Runtime migration 0035 was applied on 2026-08-01 only through the
   exact operator; its retained postflight artifact SHA-256 is
   `73085244cad0c24f22a06b22e8cf106c26f9e69a3bf5b32b9a296e995e165e6a`.
5. First run the unbound image admission verifier and require its expected
   nonzero internal preflight with every authority false. Replace the
   placeholder with the exact ID returned in step 2:

   ```console
   .venv/bin/python scripts/verify_paper_preflight_image.py \
     sha256:<64-hex-image-id>
   ```

6. Run the host-side credential-aware local preflight under the configured
   non-authorizing `PAUSED` policy. It verifies the exact schema revision,
   runtime/test database separation, artifact, inspected local image ID, and
   diagnostic telemetry configuration. With all four nonsecret account pins
   present, it also authenticates the configured account's complete historical
   binding/source lineage and exact terminal identity. It does not execute a
   bound container, select, return, resolve, or use Alpaca API credential
   variables, refresh account status, or authenticate an account-specific
   control head. Its aggregate read-only control scan requires zero `RUNNING`
   heads and reports either `absent_fail_closed` or
   `unbound_non_running_heads_present`. Missing broker credentials, alert
   routes, and an independent heartbeat remain activation blockers and must
   not be synthesized as ready.

   ```console
   .venv/bin/python scripts/verify_local_paper_smoke_preflight.py \
     --env-file /absolute/path/to/owner/.env \
     --image sha256:<64-hex-image-id>
   ```

   Require `status=smoke_preflight_ready`, `smoke_deployable=true`,
   `phase5_activation_ready=false`, and every authority flag false.
7. Run the offline no-exposure artifact verifier:

   ```console
   make no-exposure-smoke-verify
   ```

   In the operator record, mark the durable supervised invocation `UNRUN`; do
   not imply that an invocation row exists. Its claim authorizer requires an
   authenticated `RUNNING` head, which is not approved by this profile. Do not
   create or lower control state to obtain a result.
8. The 2026-07-29 sanitized Sentry transport acceptance is a dated,
   non-durable operator observation only. No checked-in credential-safe probe
   currently reproduces it. Validate only DSN configuration in this sequence;
   do not claim transport or queryable ingestion from that validation. A future
   reviewed probe must record transport acceptance separately from a trace
   being visible and queryable. Error and log ingestion require their own
   reviewed composition and must not be inferred from trace transport.
9. Record PagerDuty, Twilio, external alert delivery, and independent
   stale-heartbeat evidence as `UNAVAILABLE`; do not substitute a local log,
   terminal observation, or Sentry receipt.
10. Confirm the operator's direct observation is preflight evidence only. The
    historical enrollment attestation is not current account status,
    account-bound durable control evidence, a durable strategy invocation, or
    an independent watchdog receipt. The aggregate zero-`RUNNING` scan is not
    an account-bound control observation. Successful checks preserve only the
    configured non-authorizing `PAUSED` policy; they do not establish or mutate
    an account control head.

Any missing, ambiguous, or corrupt evidence fails the preflight. Because the
database verification has no whole-command timeout, an unresponsive check must
be stopped by the operator and recorded as unavailable rather than late-failure
evidence.

## Separate approval-gated paper-account binding

This enrollment is outside the supervised smoke sequence. It does not change
the `phase5-paper-deployment-readiness-v2` assessment, initialize an
operational-control head, transition any head to `RUNNING`, re-arm a control,
invoke a strategy, place or cancel an order, create exposure, or grant broker
effect authority. It uses only the owner's local Mac CPU/RAM and the configured
Supabase Free runtime database.

Before running it:

1. Obtain the intended paper account's provider ID independently through the
   owner-authenticated Alpaca operator interface. Do not use a discovery call
   or the response being qualified as the trust anchor. Record it as a
   canonical lowercase UUID in `AQT_PAPER_PROVIDER_ACCOUNT_ID`.
2. Configure all four nonsecret identity values in the owner-only environment:
   `AQT_PAPER_ACCOUNT_ID` for the bounded local alias,
   `AQT_PAPER_PROVIDER_ACCOUNT_ID` for the independent UUID pin,
   `AQT_PAPER_BROKER_SECRET_REF` for a canonical `secret://paper/...`
   reference, and `AQT_PAPER_BROKER_SECRET_VERSION` for its immutable version.
   Keep `ALPACA_PAPER_API_KEY` and `ALPACA_PAPER_API_SECRET` secret, require
   `ALPACA_PAPER_BASE_URL=https://paper-api.alpaca.markets`, and keep
   `AQT_DATABASE_URL` bound to the intended Supabase runtime database.
3. Review and explicitly approve both effects of the one invocation: one
   authenticated, read-only `GET` to
   `https://paper-api.alpaca.markets/v2/account`, and durable retention in
   Supabase of the exact raw response before decoding. The body contains
   balances, buying power, equity, status, and other account/economic fields.
   A received error or response that later fails qualification can also leave a
   durable raw receipt. Limit Supabase access accordingly.
4. Generate and record one new canonical lowercase UUID as the operator's
   operation ID, then run exactly one directly observed command:

   ```console
   .venv/bin/python scripts/bind_alpaca_paper_account.py \
     --env-file /absolute/path/to/owner/.env \
     --operation-id <canonical-lowercase-operation-uuid>
   ```

The command never retries. Exact replay of the same operation ID fails before a
second provider request. A different operation ID represents a new approved
attempt and must never be generated or used as an automatic retry. After a
timeout, transport failure, raw-only receipt, pin mismatch, or ambiguous exit,
preserve and review the Supabase evidence before separately approving any new
attempt.

If and only if the reviewed evidence is exactly one generation-one
lease/release, one reconciliation permit, one retained successful account JSON
response, no binding, a clear lease head, unchanged non-running control, and no
other account-local state, the command exposes a separate single-shot recovery
mode. Use it only after the decoder/profile fix is committed, reviewed, and
green in CI; re-decode the retained bytes offline; obtain a fresh explicit
approval for one second `GET /v2/account`; and generate a distinct new
operation UUID:

```console
.venv/bin/python scripts/bind_alpaca_paper_account.py \
  --env-file /absolute/path/to/owner/.env \
  --operation-id <new-canonical-lowercase-operation-uuid> \
  --recovery-from-operation-id <generation-one-operation-uuid> \
  --authorize-second-account-get
```

Both recovery flags are mandatory and the old and new operation IDs must be
different. Recovery preserves the original lease, permit, and raw receipt,
acquires generation two, and invokes the unchanged bounded account observer at
most once. It cannot resume any other checkpoint and cannot authorize
generation three. If the second attempt fails or exits ambiguously, preserve
all state and stop for a new architecture and security decision.

On success, the predecessor-linked binding history is durable, but its runtime
freshness window is at most five seconds. It is identity evidence for that
receipt window, not a persistent readiness grant, account-economics fact,
reconciliation result, control authorization, or Phase 5 activation. This
runbook records the 2026-07-31 successful historical enrollment described
above. ADR 0089 can reauthenticate its exact terminal identity after expiry
without making another provider request.

## Deferred timed drills

These wall-clock drills are not authorized by the current preflight-only
profile. Record them as `UNRUN` or `UNAVAILABLE`, not passed. A later reviewed
profile must bind local host, image, schema, database, account, strategy,
policy, and actor/authority digests before executing them:

- kill-state command and process-restart behavior;
- strategy timeout/crash/protocol failure;
- external alert failure as explicitly `UNAVAILABLE`;
- total alert unavailability preserving `PAUSED`;
- local process loss observed directly by the operator;
- market-data gap and SIP entitlement loss;
- broker disconnect and `UNKNOWN` containment;
- moderate-policy risk trip at each `REJECT`/`PAUSED`/`HALTED` boundary;
- local image rollback to a known image while remaining `PAUSED`; and
- logical database export/restore only where it can be proven without claiming
  an undeclared RPO/RTO.

Local pytest evidence and distinct provider IDs do not qualify these drills.
None of these supervised drills qualifies as alert-channel independence,
stale-host detection, or an unattended game day. Those gates remain open until
a later profile provides external routes and a watchdog.

## Rollback

1. The current preflight authenticates no account-bound durable control head;
   its aggregate scan cannot substitute for one. If a later composition supplies
   a verified head, preserve or raise it to `HALTED` when deployed state is
   ambiguous; do not synthesize that transition for this preflight.
2. Stop new local image starts and retain the current database and diagnostic
   evidence.
3. Resolve and start only the previous recorded exact local `sha256:` image ID;
   do not use a mutable tag and do not roll the schema backward.
4. Run that exact image's compatibility preflight against the current schema.
5. Re-run no-exposure and Sentry-configuration checks. Keep Sentry transport,
   provider delivery, and watchdog evidence explicitly `UNAVAILABLE` unless a
   separately reviewed probe produces new evidence.
6. Do not re-arm under this profile. A future profile may permit re-arm only
   through the separately authenticated exact-head workflow after
   authoritative reconciliation and every blocker disposition is complete.

Never restore a database over newer incident, order, fill, ledger, control, or
alert evidence merely to make an older image start.
