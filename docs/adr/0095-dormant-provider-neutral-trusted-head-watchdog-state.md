# ADR 0095: Dormant provider-neutral trusted-head watchdog state

- Status: Accepted (preparatory and dormant)
- Date: 2026-08-02
- Extends: [ADR 0094](0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md)

## Context

ADR 0094 defines signed, gap-free trusted-time head checkpoints in a separate
Supabase project. At this ADR's acceptance, project provisioning and first
external enrollment were incomplete. They subsequently completed: ADR 0097's
approved `new` operation confirmed sequence 1, and ADR 0098 authenticates the
retained claim/outcome while keeping persistent start and sequence 2 blocked.
The local supervisor also cannot prove its own continued operation after it
dies.

A valid checkpoint signature proves that the admitted private-key holder signed
those exact record bytes. It does not prove that a caller read the bytes from
the admitted provider, that the record was the provider namespace's current
terminal, that no higher sequence existed, or that the namespace advanced
between observations. A caller-supplied monotonic value likewise does not prove
an independent observation instant.
A later watchdog therefore needs an external issuer/provider adapter that
seals those remote and timing facts rather than accepting them as arguments.

That future runtime needs a small deterministic state contract. Implementing
the pure state transition makes its failure semantics reviewable without
claiming that the observer, alert path, or trading consumer exists. The first
two steps of this normative order are now complete; step 3 must wait for the
ADR-0098 outcome-bound start and graceful-stop boundary:

1. complete and retain reviewed evidence for the separate anchor project;
2. separately approve and perform the first external enrollment, retaining
   the sequence-1 full-audit and exact second-`GET` receipt evidence;
3. implement and qualify the sealed terminal-observation issuer/provider
   adapter; and only
4. deploy and qualify an independent watchdog runtime and its later consumers.

Local preparatory code does not satisfy or reorder either prerequisite.

## Decision

Define pure contract
`phase6e-provider-neutral-trusted-head-watchdog-state-v1` in the
[application-layer watchdog state](../../packages/application/trusted_time_watchdog.py).
It owns no network, database, provider, process, or clock dependency. Callers
submit candidate checkpoint bytes and monotonic values, both of which remain
untrusted observations. The reducer authenticates canonical form, signature,
authority identity, sequence, predecessor, and value order. Its output is
application-sealed and bound to the exact contract and admitted authority, but
no consumer exists.

The reducer never reports `CURRENT` or `STOPPED` and never calculates staleness
from a caller-supplied candidate time. Every nonfatal result is `UNAVAILABLE`
with exactly one of `STARTUP_NO_BASELINE`, `BASELINE_ONLY`,
`PROVIDER_TERMINAL_PROOF_ABSENT`, or `PROVIDER_UNAVAILABLE`. The first valid
checkpoint establishes only an authenticated-bytes baseline. An exact signed,
gap-free successor, including `clean_stop`, advances chain diagnostics but is
`PROVIDER_TERMINAL_PROOF_ABSENT`; it proves a relationship between submitted
records, not provider origin, remote terminality, remote advancement, stop
state, freshness, or liveness. Re-reading an unchanged tip and reporting
provider absence likewise cannot create those facts. Caller-supplied monotonic
values support only fail-closed input-order checking; they are not observation
or age evidence.

Every malformed record, invalid signature, identity mismatch, fork, rollback,
sequence gap, predecessor mismatch, or monotonic-clock regression fails
closed. A caller's provider-unavailable report is distinguishable from
authenticated corruption but does not prove a provider outage or establish or
restore provider observation.

All emitted readiness, operational-control, arming, exposure/new-exposure,
broker-action, alert-delivery, automatic-rearm/resume, paper-trading, and
live-trading authority flags are false. No reducer result is authority.

ADR 0109 now supplies a clean-stop-specific code-only example of the sealed
terminal-observation mechanics with no live, watchdog, or effect consumer
except ADR 0111's dormant zero-caller composition: full authenticated pass A, matching
names pass B, a late terminal GET, empty next-sequence check, final provider
identity, equal SQL projections around the provider reads, and an issuer-owned
suspend-aware deadline. It does not complete step 3 above because it is not a
qualified or deployed watchdog adapter, grants no freshness/currentness, uses
the existing writer-capable provider credential behind only a method-narrowed
wrapper, and has no watchdog consumer. The future deployed runtime, not dormant
v1 or the ADR-0109 clean-stop result, must apply the 360-second stale policy
with equality stale and every stale result unavailable. Raw bytes,
caller-supplied time, and one past clean-stop observation must never be upgraded
into a continuing currentness lease.

This preparatory slice deliberately supplies no Supabase or other provider
adapter, runtime process or container, independent external failure domain,
alert delivery, readiness or operational-control integration, new-exposure
gate, exact-head manual re-arm integration, deployment, qualification drill,
or Phase 6 exit evidence. It does not consume the supervisor worker's local
status as proof of independent liveness.

## Consequences

The transition semantics can be reviewed and exercised locally before the
external topology is fully provisioned and qualified. The reducer can reject
malformed or contradictory submitted chains without converting a valid chain,
a caller clock, or sealed reducer evidence into provider-terminal or liveness
evidence.

The current deployment still has no persistent trusted-time topology or
independent watchdog. Although separate-project provisioning and first
enrollment are complete, the ADR-0098 outcome-bound start/graceful-stop
boundary and independent runtime are not deployed or qualified. ADR 0109's
clean-stop-specific observer is code-only, has no live, watchdog, or effect
consumer except ADR 0111's dormant zero-caller composition, and is not a
qualified watchdog issuer. This contract therefore remains dormant library code. Local
implementation or unit-test results are not provider observation, deployment,
drill, alert delivery, consumer, or Phase 6 exit evidence.
