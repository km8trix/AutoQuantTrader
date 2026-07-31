# ADR 0086: provider-neutral trusted-time monitor

- Status: Accepted
- Date: 2026-07-28

## Context

The operational budget requires host clock offset to be sampled at startup and
at least every 30 seconds while armed. Absolute offset below 250 milliseconds
is healthy, offset from 250 through 1,000 milliseconds is warning evidence, and
offset above 1,000 milliseconds is a hard failure. A hard failure must block
arming and new exposure, and later health may support manual re-arm only after
a continuous 60-second recovery interval.

The existing `Clock` ports establish only that a caller supplies a
timezone-aware UTC instant. They do not retain a trusted source identity,
correlate host UTC with monotonic time, classify offset, prove sampling cadence,
or prove the recovery interval. Operational re-arm already reserves a
`clock_healthy` prerequisite, but no typed source evidence existed from which an
authoritative verifier could derive it.

Selecting an actual time source, authentication mechanism, host identity,
deployment scheduler, storage topology, or operational-control integration is
a deployment decision. The repository must not invent those authorities merely
to define and test the invariant.

## Decision

Add the pure `phase6a-provider-neutral-trusted-time-v1` domain contract and one
in-memory, provider-neutral application probe step.

One `TrustedTimeSample` binds:

- the source ID and source-authority digest supplied by deployment;
- the host ID and process-local monitor epoch;
- a gap-free positive sequence number and source-evidence digest;
- exact UTC probe start, probe completion, and authenticated source instant;
  and
- the corresponding monotonic probe start and completion values.

The signed offset is derived from the authenticated source instant and the
midpoint of the local UTC probe interval. Callers do not supply a separate
offset claim. Samples, policies, states, and evaluations use exact types,
timezone-aware UTC values, canonical payloads, and deterministic SHA-256
semantic identities. The approved policy is pinned at the public reduction
seam; callers cannot inject a looser policy. Derived states carry a private
payload seal, and each evaluation recomputes the reducer result, so replacing a
health, latch, recovery, or continuity field through the supported API is
rejected. This seal is deterministic tamper detection, not authentication: a
bare state is not a durable trust boundary and cannot independently authorize
control.

The fixed v1 policy classifies the absolute derived offset as follows:

- `<250 ms` is `HEALTHY`;
- `250 ms <= offset <= 1,000 ms` is `WARNING`; and
- `>1,000 ms` is `BLOCKED` and latches the hard-failure state.

Magnitude equality remains within the reviewed limit. Freshness is stricter:
the latest sample age must be `<30 s`, so age equality is stale. A replacement
sample may complete exactly 30 seconds after its predecessor and still preserve
cadence; a larger gap fails closed.

Each source request receives a monotonic deadline exactly one second after the
local start reading. A successful sample may span at most one second, with
equality accepted. Its UTC and monotonic elapsed intervals may differ by at most
250 milliseconds, also with equality accepted. A deployment source adapter is
responsible for enforcing the supplied deadline; successful overrun evidence is
rejected even if that adapter returns it.

Every successor sample must retain the same source, authority, host, and monitor
epoch; increment the sequence by exactly one; and preserve non-regressing UTC
and monotonic probe order. Missing or unavailable evidence, stale evidence,
identity changes, sequence discontinuity, cadence gaps, and UTC or
monotonic regression produce explicit blocked evidence. Warning, unavailable,
or discontinuous evidence resets the continuous healthy interval rather than
inventing a zero offset or silently bridging the gap. An identity-conflicting
sample is not promoted to the retained baseline, and the application seam
rejects a conflicting binding before invoking its source. Repeated readings
under the conflicting identity therefore cannot self-establish a recovery
chain.

A healthy chain begins at the completion of its first qualifying sample and
must remain gap-free for at least 60 monotonic seconds. At equality, the state
may expose `clock_recovery_qualified`. That field is time-health evidence only:
it never clears the hard-failure latch, changes operational control, authorizes
arming or new exposure, or performs re-arm. The local chain has no latch-clear
transition. Only a separately authenticated, exact-proof manual-control
handoff may authorize a new monitor epoch. A cold start or process restart
begins without authority and must establish a new local chain.

`run_trusted_time_probe` performs one injected request through UTC and monotonic
clocks and a provider-neutral source port. It supplies the fixed monotonic
deadline but does not implement an in-process watchdog. A deployment-supplied
binding pins the expected source, authority, host, and epoch. Source exceptions
are sanitized; unsupported, overlong, cross-clock-divergent, and
source-identity-mismatched readings retain no sample and fail closed. The
result contains only probe status and the domain evaluation.

## Consequences

Local code can now create deterministic, tamper-sensitive clock-health evidence
and test the reviewed magnitude, freshness, cadence, continuity, latch, and
recovery boundaries without network, database, scheduler, or trading authority.
The contract distinguishes a healthy current sample from a completed recovery
window and cannot automatically lower an operational-control state.

This decision does not select or authenticate a real NTP, chrony, cloud, or
other trusted-time source. It adds no background scheduler, SQL retention,
startup/readiness gate, dashboard or API field, alert, advanced-risk producer,
account-fenced new-exposure check, control trip, or authoritative manual re-arm
composition. It also adds no adapter-level timeout implementation or
process-level watchdog. It does not define or cap authenticated source
uncertainty/dispersion, so a selected adapter must provide a reviewed bound and
classification must conservatively include it before admission. Durable use
also requires authenticated trusted-head provenance rather than accepting a
bare deterministic state. This decision therefore does not implement deployed
clock-drift supervision and does not satisfy the Phase 6 clock-drift game-day
gate.

This decision adds no schema or migration.
