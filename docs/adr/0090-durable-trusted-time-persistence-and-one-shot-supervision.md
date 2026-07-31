# ADR 0090: durable trusted-time persistence and one-shot supervision

- Status: Accepted
- Date: 2026-07-31

## Context

ADR 0086 defines a pure provider-neutral trusted-time reducer and one injected
probe. Its process-local state proves offset, cadence, freshness, latch, and
healthy-recovery semantics, but it deliberately has no durable provenance,
restart fencing, scheduler, source selection, or control authority.

Persisting a reducer-produced `TrustedTimeState` directly would be unsafe. Its
private seal is deterministic tamper detection, not durable authentication, and
monotonic values cannot be continued across a process restart. A durable
supervisor must instead retain the exact public inputs, reconstruct every state
through the approved reducer, and prevent a stale process from appending after a
new monitor epoch replaces it.

This local slice must not choose a real time source or turn clock evidence into
arming, exposure, operational-control, alert, or re-arm authority.

## Decision

Add the `phase6a-durable-trusted-time-persistence-v1` contract with three
durable structures:

1. immutable monitor-epoch registrations form a gap-free, predecessor-linked
   history per host;
2. immutable probe evaluations form a gap-free, predecessor-linked attempt
   history within one epoch; and
3. one mutable host head identifies the exact active epoch and committed
   evaluation tip.

Starting a process always registers a newly generated monitor epoch. The
repository returns an opaque, process-local session capability bound to the
issuing repository instance and process. There is no API that resumes an epoch
from a durable ID. A new epoch always begins with `prior=None`; persisted
monotonic values, hard-failure latch state, healthy-chain origin, and recovery
qualification never cross a restart boundary.

The epoch registration atomically replaces the host head and thereby fences
every older session. Replacing an epoch does not clear an operational incident,
prove `clock_healthy`, or lower operational control. It only starts a new local
evidence chain.

Probe attempt sequence and domain sample sequence are deliberately separate.
Every attempt is durably represented, including source-unavailable,
source-identity-mismatch, and invalid-reading outcomes. Only a `recorded`
attempt contains sample inputs. Sample-free failures retain no fabricated
offset or source instant.

One durable probe step has three stages:

1. `prepare_probe` authenticates the current epoch registration, host head, and
   complete current-epoch history, then reconstructs the exact prior state;
2. the existing ADR 0086 probe is invoked exactly once outside any database
   transaction; and
3. `append_probe` locks and reauthenticates the expected host head, inserts the
   immutable evaluation, and advances the head atomically.

The append is an exact compare-and-swap. If another probe or epoch rotation wins
first, the stale result is discarded and is not retried against the newer
head. Concurrent source reads are possible, but at most one result for a given
predecessor becomes durable. An append committed before epoch replacement
remains historical; no old session may append after replacement commits.

Durable authentication replays each row from public `TrustedTimeSample` inputs
through `evaluate_trusted_time`. Stored health, reason, latch,
healthy-since, recovery, state, and evaluation projections must exactly equal
the recomputed result. Persistence never reconstructs or trusts the private
state seal directly. Forks, gaps, orphans, deleted tails, rewound or foreign
heads, identity or policy substitution, malformed payloads, and derived-field
tampering fail closed.

The histories are tamper-evident, not externally authenticated or rollback
proof. A future authenticated anchor is required before a database head can be
treated as independent authority.

The one-shot application result is explicitly non-authorizing. It exposes no
control command, broker action, arming, new-exposure, automatic-rearm,
readiness, alert, scheduler, or strategy-invocation authority.

## Consequences

Trusted-time evidence can now survive within one process epoch, be inspected
after restart, and reject stale-process commits without holding a transaction
across source I/O. Local SQLite and designated PostgreSQL test coverage can
exercise corruption, rollback, and compare-and-swap behavior.

This decision adds no real NTP, chrony, cloud, or other source; no source
authentication or uncertainty bound; no deployed host identity; no background
scheduler or watchdog; no API or dashboard; no alert delivery; no operational
control or exposure gate; and no manual re-arm proof. It does not authorize
paper or live trading.

## Deployment observation

On 2026-07-31, the owner approved applying only migration 0034 to the runtime
Supabase database. The migration advanced revision 0033 to 0034
transactionally. Post-migration verification found all three trusted-time
tables with zero epoch, evaluation, and head rows, and the full operational
schema integrity gate passed.

This observation does not select or authenticate a source, establish a source
uncertainty bound, choose deployed host/failover identity, start a persistent
supervisor, or wire evidence into readiness, alerts, control, exposure, or
re-arm. Each of those actions still requires separate owner approval.
