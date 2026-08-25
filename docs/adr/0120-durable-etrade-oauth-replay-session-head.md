# ADR 0120: Durable E\*TRADE OAuth replay and session head

- Status: Accepted
- Date: 2026-08-25
- Extends: [ADR 0113](0113-recorded-offline-etrade-provider-foundation.md) and
  [ADR 0118](0118-pure-etrade-oauth1-signing-and-supervised-session.md)

## Context

ADR 0118 deliberately keeps its replay guard and supervised session immutable
and in memory. Threading the latest objects rejects replay and rollback inside
one process, but reusing an older state/guard can fork the history after a
restart or between concurrent processes. Its sealed verifier capability also
does not establish a durable current session.

The next safe dependency is a local atomic current-head coordinator. It must
persist enough sanitized evidence to reconstruct the complete replay and
session chain without becoming a secret store, provider client, authenticated
response boundary, account binding, or broker authority. Consumer-secret
reference revisions can rotate, so the durable head cannot be keyed by a
revision-specific reference digest: that would permit a second head for the
same environment and secret scope.

## Decision

1. Implement Phase 4AM in
   `packages/persistence/etrade_oauth_coordinator.py` under contract
   `phase4am-durable-etrade-oauth-replay-session-head-v1`. The public
   repository accepts only exact ADR-0118 sanitized session states, replay
   guards, and a previously authenticated durable snapshot. It accepts no
   credential value, signature, header, URL, resolver, clock, nonce generator,
   provider callback, network client, account identity, order, or trading
   command.
2. Migration 0038 adds two tables:

   - `phase4_etrade_oauth_session_events` is an immutable, sequence-ordered,
     predecessor-linked journal. Each row retains the stable scope identity,
     current typed consumer-reference version/digest, endpoint-profile digest,
     prior and current sanitized session digests, canonical sanitized state
     evidence, replay-guard digest, at most one newly consumed fingerprint, and
     at most one corresponding signing generation/time high-water update.
   - `phase4_etrade_oauth_session_heads` has exactly one current row per typed
     environment plus consumer-secret scope. It retains the current reference
     revision/digest and exact event, session, replay-guard, and sequence
     cursor. The stable scope digest excludes consumer-reference version, so a
     reference rotation cannot create another durable history.

3. Initialization admits only ADR-0118's exact token-empty generation-one
   state and empty replay guard. Every advancement supplies the exact prior
   `EtradeOAuthDurableSnapshot`, successor state, and successor replay guard.
   Under the database write lock, the repository compares the supplied event,
   session, replay-guard, and sequence cursor with the fully reconstructed
   current snapshot. A replay-only event can therefore move the durable head
   even when the session-state digest is unchanged; a later state-only command
   from the older snapshot loses as stale.
4. One event can append zero or one fingerprint. Existing fingerprints must be
   an exact ordered prefix and can never disappear, reorder, change, or repeat.
   Existing signing high-water scopes can never disappear; at most one scope
   can be added or advanced with a fingerprint, and its generation and Unix
   seconds cannot regress. Session generation, token-reference high-water,
   trusted-time high-water, environment, consumer scope, and endpoint profile
   also cannot regress or change. A changed session must name the exact current
   session digest as predecessor.
5. An exact retry recomputes the proposed event from the complete supplied
   prior/proposed pair. It converges only when that event is the already-current
   event. A stale branch, rollback, replay, conflicting identity reuse, changed
   retry, or later-head retry fails deterministically. SQLite uses
   `BEGIN IMMEDIATE`; PostgreSQL takes the exact head row `FOR UPDATE`; the
   final compare-and-swap requires the prior event and sequence, so two
   conflicting concurrent advancements have exactly one winner.
6. Every read selects all events for the stable scope and reconstructs the
   session and replay guard from the root. It recomputes every sanitized state,
   state payload digest, event canonical payload/digest, predecessor, replay
   delta, replay-guard digest, sequence, stable environment/scope digest, and
   final head cursor. Orphaned event/head scopes and any duplicated-field,
   cross-scope, event, guard, or head tampering fail closed before a snapshot is
   returned. Operational schema verification authenticates every durable
   scope.
7. A consumer-reference rotation is permitted only from ADR-0118's token-empty
   `NEEDS_REQUEST_TOKEN` state after explicit reauthorization has started. It
   must strictly increase the typed nonsecret reference version inside the
   same environment/scope and binds the prior state and both reference digests.
   Rotation from request-token, authorization, active, inactive, expired,
   revoked, or reauthorization-required states is rejected so a new consumer
   reference cannot be paired with tokens issued under the old consumer.
8. Persisted content is allowlisted sanitized metadata. Consumer keys,
   consumer/token secrets, request/access token values, verifier values,
   signatures, Authorization or Cookie headers, request URLs/query strings,
   signature bases/keys, authorization URLs, and other credential-bearing
   material are neither accepted nor stored. Reference scope/version and
   semantic digests are nonsecret identities, not credential resolution.
9. Migration downgrade takes an `ACCESS EXCLUSIVE` lock on PostgreSQL and
   refuses to remove either table while any durable OAuth history exists.
   SQLite enforces the same nonempty refusal. The migration is additive and
   does not reinterpret any Alpaca, ADR-0113, or ADR-0118 evidence.
10. All authority flags remain false. This coordinator authenticates only its
    local sanitized journal and current cursor. It does not authenticate an
    E\*TRADE response or provider origin, resolve or retain credentials, open a
    browser/OOB handoff, perform transport, schedule renewal, bind an account,
    call a broker, start paper/live trading, or authorize an effect.

## Consequences

Reusing a stale ADR-0118 state or replay guard can no longer fork the accepted
local durable history. Restarts and concurrent processes can reconstruct one
authenticated replay/session prefix, exact retries converge, conflicting
advancements select one database winner, and consumer-reference rotation stays
on the original environment/scope head.

The result is still not an OAuth runtime. Durable currentness means only that
this local sanitized SQL prefix is current. A later reviewed slice must add
ephemeral secret resolution, authenticated raw-first token response evidence,
interactive OOB handoff, transport/proxy/redirect enforcement, operational
renewal supervision, and authenticated account binding before any provider
call can be considered. None of those capabilities or authorities is implied
by a durable event, replay fingerprint, digest, or head.
