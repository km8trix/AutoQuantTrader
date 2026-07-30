# ADR 0088: fail-closed paper smoke deployment profile

- Status: Accepted
- Date: 2026-07-29
- Amended: 2026-07-29 (owner-approved local smoke profile; separate enrollment
  boundary documented)

## Context

Phase 5 has local contracts for operational control, advanced risk, supervised
strategy execution, critical-alert delivery, tracing, and operational drills.
ADR 0087 also fixes an executable no-exposure strategy artifact. None of those
contracts selects a compute host, managed database, telemetry backend, alert
providers, paper-account binding, secret boundary, or runtime activation
policy.

The first smoke preparation must verify packaging, migration readiness,
owner-observed local execution, read-only durable-schema access, and telemetry
configuration without creating a shortcut to exposure. It must also keep the
loopback-only operations API out of any public topology and distinguish a
configured diagnostic provider from evidence that ingestion and querying work.
The current v2 boundary is a preflight: it does not compose a worker, write
durable strategy state, or export runtime telemetry. The owner has elected to
use existing local Mac CPU/RAM and a Supabase Free project, and to defer hosted
compute, PagerDuty, and Twilio. The narrower profile is therefore a supervised
no-exposure preflight, not an always-on deployment or Phase 5 activation
candidate.

## Decision

Adopt the fixed `phase5-paper-deployment-readiness-v2` profile:

1. The only environment is `paper`. Live credentials, live secret references,
   public operations endpoints, automatic re-arm, and mutable promotion of
   paper state are rejected. `PAUSED` is the configured non-authorizing policy.
   The current preflight creates no control state and authenticates no
   account-bound durable head. It performs only an aggregate read-only safety
   scan: zero `RUNNING` heads is required, and the public observation is either
   `absent_fail_closed` or `unbound_non_running_heads_present`. Any observed
   `RUNNING` head, ambiguity, or corruption fails closed. Health recovery,
   process restart, and successful smoke preparation cannot authorize a lower
   state.
2. Build one local production image from digest-pinned bases, resolve its exact
   `sha256:` image ID, and run the unbound image verifier against that exact ID
   on the owner's local Mac CPU/RAM. Run the credential-aware database/Sentry
   checks as a separate host-side process; those checks inspect the image ID but
   do not inject credentials into or execute a bound container. Neither process
   has a public URL, and the verified image has no inbound port or persistent
   container disk; PostgreSQL remains external. Keep the Mac awake for the
   operator-declared smoke window, observe each process directly, and stop if
   the host sleeps, reboots, loses network, or loses supervision.
   GitHub checks must pass on the exact source revision before the image is
   used. Schema expansion remains a distinct command, and failed readiness
   makes the process exit nonzero. Hosted or unattended compute is explicitly
   deferred. The operations API and dashboard remain loopback-only and are not
   part of the smoke process.
3. Use the owner's Supabase Free PostgreSQL project for paper smoke state via
   `AQT_DATABASE_URL`. Keep `AQT_TEST_POSTGRES_URL` bound to a different
   database and never use the destructive test DSN as runtime state. Use an
   SSL-required endpoint compatible with the local client. Record a logical
   export before migration or another destructive drill where the Free project
   and network path support it; do not claim managed backup, point-in-time
   recovery, retention, RPO, or restore evidence that has not been proven. An
   exposure-capable successor must revisit database isolation, capacity,
   backup, and restore requirements.
4. Record one intended Alpaca paper account for later binding, but leave it
   unbound during the current preflight. The v2 preflight consumes no Alpaca
   UUID, base URL, or credential and proves no authenticated account or
   account-bound control state; its aggregate zero-`RUNNING` scan is
   non-authorizing. No Alpaca live base URL or live credential is accepted by a
   future binding. ADR 0068's moderate policy requires authoritative
   consolidated SIP evidence, but neither that policy nor an Alpaca data-plan
   upgrade is part of this smoke. Until authenticated account, complete risk,
   and reconciliation producers exist, the local profile may verify only the
   ADR 0087 no-exposure artifact and remains fail closed.
   A separate owner-operated enrollment command may compose ADR 0044 only
   after its own explicit approval. It requires a canonical lowercase provider
   account UUID obtained independently of the response plus the four nonsecret
   `AQT_PAPER_ACCOUNT_ID`, `AQT_PAPER_PROVIDER_ACCOUNT_ID`,
   `AQT_PAPER_BROKER_SECRET_REF`, and
   `AQT_PAPER_BROKER_SECRET_VERSION` values. One canonical operation UUID
   permits at most one fixed authenticated paper `GET /v2/account`; there is no
   retry, exact replay fails before a second request, and any different
   operation UUID is a separately approved attempt. Every bounded response is
   retained exactly in Supabase before decode and can contain balances, buying
   power, equity, status, and other account/economic fields. Only an observed
   UUID equal to the independent pin can append a secret-free binding. This is
   an identity-enrollment operation, not part of the v2 preflight or a Phase 5
   activation.
5. Pin the checked-in no-exposure strategy ID, version, configuration digest,
   artifact digest, and manifest digest in the deployment plan. The first
   local smoke verifies that artifact and its image packaging without starting
   the durable claim path. That path requires an authenticated account-bound
   `RUNNING` head, while this owner-approved profile configures only a
   non-authorizing `PAUSED` policy and accepts only an aggregate observation
   with zero `RUNNING` heads; no transition to `RUNNING` is approved. A future
   separately reviewed invocation may execute only the same zero-intent
   artifact and would still have zero broker-effect authority.
6. Use the existing Sentry `autoquant-trader` project for diagnostic
   OpenTelemetry export. Diagnostic payloads sent to Sentry retain no
   application/provider credentials, order payloads, positions, symbols,
   prices, or other sensitive account content. Access is operator-only with
   MFA. The current implementation covers OTLP traces only. PostgreSQL remains
   authoritative. Transport acceptance is not proof that a trace is queryable,
   is not a critical-alert delivery receipt, and cannot authorize trading.
7. Defer PagerDuty, Twilio, and the external stale-heartbeat watchdog. Their
   tested local adapters remain available for a later reviewed profile, but
   this profile binds no provider routes, destination, recipient roster,
   escalation schedule, or independent worker-loss detector. Durable internal
   alert incidents are therefore not externally delivered. Sentry must never
   be relabeled as paging or watchdog evidence.
8. Do not activate the external-route-dependent total-alert-failure policy.
   Missing routes preserve or raise operational control to at least `PAUSED`,
   prevent unattended operation, and remain explicit blockers for Phase 5
   deployment readiness. They never trigger automatic failover to exposure or
   automatic re-arm.
9. Keep local paper credentials and DSNs only in the owner's untracked `.env`
   with mode `0600` or a stronger local secret store. Runtime adapter
   configuration may receive resolved secrets ephemerally and must redact
   them. Secret values, DSNs, provider routing keys, phone numbers, email
   addresses, and Sentry client keys are excluded from durable configuration
   models, semantic identities, logs, receipts, and checked-in files.
   The four `AQT_PAPER_*` identity values in decision 4 are nonsecret
   configuration: the secret reference must use `secret://paper/...`, its
   version must be immutable safe text, and neither may contain credential
   material.
10. The current host-side packaging preflight can bind only the exact inspected
    image ID, schema revision, database, no-exposure artifact, and diagnostic
    telemetry configuration. Operator identity and the declared observation
    window remain directly supervised procedure, not encoded assessment
    evidence. Within that assessment, the intended paper account remains
    explicitly unbound; only the aggregate zero-`RUNNING` safety scan is
    reported, not authenticated account-specific control evidence. External
    notification routes and an independent heartbeat policy are deliberately
    unavailable and remain deployment-readiness blockers rather than smoke
    prerequisites.
    Missing authoritative risk sources, correction-safe fill application,
    qualified reconciliation, trusted-time persistence, manual re-arm proof,
    or deployed wall-clock drills remains an explicit blocker. The first
    profile therefore records approved decisions without declaring the Phase 5
    exit gate complete.

## Implementation status

The selected local boundaries have non-authorizing implementations:

- a production container built from digest-pinned bases runs as UID/GID 10001
  with root-owned, non-group/other-writable strategy inputs, no inbound port,
  and a paper-default one-shot admission command; CI builds the image, inspects
  those invariants, and requires the unbound preflight to exit `2`. The local
  workflow separately resolves and records the exact inspected `sha256:` image
  ID rather than treating its mutable tag as an immutable reference;
- a credential-aware local preflight validates the owner-only environment
  file, distinct Supabase runtime/test identities, session-mode TLS, the exact
  migrated schema, inspected local `sha256:` image ID, Sentry DSN shape, and
  pinned artifact sources. It also performs a read-only aggregate control-head
  scan and rejects any `RUNNING` head before reporting fail-closed
  smoke-preflight readiness;
- an owner-operated `scripts/bind_alpaca_paper_account.py` command separately
  composes one ADR 0044 account read on the local Mac against the Supabase Free
  runtime database. It enforces the independent provider UUID pin, four
  nonsecret identity values, one-operation/one-request boundary, no retry,
  raw-before-decode retention, matching identity, and secret-free durable
  binding history while leaving every control and broker-effect authority
  false;
- a Sentry Cloud OTLP/HTTP trace-exporter factory validates a project DSN,
  derives the fixed trace endpoint and `X-Sentry-Auth` value while redacting
  that value from representations and failures, enforces the
  `autoquant-trader`/release/`paper` resource pins, and removes non-allowlisted
  span content before export;
- `pagerduty-events-v2-primary` and
  `twilio-messaging-service-sms-escalation` retain tested provider-call
  implementations, but both are deferred and unbound in this profile.

The Sentry implementation currently covers OTLP traces, not error or log
capture. On 2026-07-29, the operator supplied a DSN outside the repository and
observed provider transport acceptance for one sanitized synthetic export.
That was a non-durable setup observation, not checked-in or reproducible
readiness evidence; trace queryability has not been proven. The alert
implementations are unit-tested with injected transports and remain
deliberately unconfigured. The paper worker does not yet compose the exporter
or alert routes and does not establish retention/sampling enforcement,
recipient delivery, operational independence, or an independent stale-host
signal. Durable worker/exporter composition, queryable-ingestion evidence, and
a durable strategy invocation remain open. Unattended runtime, external alert,
watchdog, and timed failure-domain evidence remain deferred deployment
blockers.

The account-enrollment command is implemented procedure, not execution
evidence. No real provider request or durable account binding is claimed by
this ADR. Even if a separately approved invocation succeeds, the binding is
fresh for at most five seconds and does not initialize or mutate operational
control, assign the moderate policy, invoke the no-exposure strategy, authorize
an order, create exposure, or satisfy the Phase 5 exit gate.

The `phase5-paper-deployment-readiness-v2` assessment now fixes local
owner-supervised compute, Supabase Free, Sentry, and deferred external alerts.
The credential-aware host-side preflight can report `smoke_preflight_ready`
after the exact packaging/database/telemetry/artifact checks pass. Local
supervision and deferred external alerts are permanent activation blockers, so
even complete synthetic provider evidence cannot make the profile Phase 5
ready.

Successful exact-ID image inspection, Supabase connectivity/schema validation,
Sentry configuration validation, and offline artifact verification constitute
only local packaging/DB/telemetry/artifact preflight evidence. The dated
synthetic Sentry transport observation remains separate and non-durable. None
of this proves an authenticated Alpaca account, an authenticated account-bound
control head, or a durable strategy invocation. The aggregate database
observation proves only that no `RUNNING` head was visible during its read. The
durable claim authorizer would require a verified account-bound head in
`RUNNING`; this profile configures only a non-authorizing `PAUSED` policy and
approves no transition. The invocation is intentionally unrun and Phase 5
remains open.

## Consequences

The local topology is no longer implicit. Configuration and preflight code can
reject live, public, secret-bearing, or provider-substituted plans before
network or broker effects. The verified no-exposure artifact gives packaging
and subprocess checks a real target while preserving zero exposure authority.
Using local compute avoids a hosted-worker cost, but host sleep, reboot,
network loss, and loss of operator attention end the operator-declared window
rather than trigger an independent notification. The database verifier enforces
per-connect, pool, statement, and lock limits but has no whole-command deadline,
so operator supervision must treat an unresponsive check as unavailable
evidence rather than as a passed bounded probe.

A separately approved enrollment deliberately stores the exact bounded Alpaca
account response in Supabase before it is decoded. Those raw bytes may contain
sensitive account/economic fields and must remain operator-restricted; they are
not canonical account economics, risk capacity, reconciliation, or trading
authority. Exact operation replay cannot send twice, while a new operation ID
is a new approved attempt and must not be generated as an automatic retry.

This ADR does not purchase accounts, deploy a hosted service, upgrade Supabase
or Alpaca, register a Twilio sender, create a PagerDuty service, configure
recipients, or prove an external route. Those actions are deferred rather than
required for the directly supervised preflight. It also does not invent the
authoritative risk, fill, reconciliation, trusted-time, re-arm, or drill facts
that the current repository deliberately lacks. Until those facts and the
deferred external safety paths exist, `smoke_preflight_ready` may describe
only the fail-closed packaging preflight; the configured non-authorizing
`PAUSED` policy and not-Phase-5-ready remain the only valid activation
conclusions.
