# ADR 0048: durable normalized UNKNOWN-lookup reconciliation evidence

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4I retains one authenticated, raw-first client-order lookup for an exact
submission attempt that was terminal `UNKNOWN`, and Phase 4J durably bounds
when those lookups may be attempted. The authenticated receipt deliberately
stores only a small scalar summary. Its exact Phase 4C raw source still
contains the complete strictly decoded Alpaca Order observation, including
nanosecond provider timestamps, replacement links, request economics, and
cumulative fill fields.

That evidence is useful to reconciliation, but it is not a broker event.
Arrival order is not provider revision order, a REST Order object's cumulative
fill values do not identify individual executions, and a transient 404 does
not prove that the submission never reached the broker. Applying any of those
values directly to the canonical order or execution reducers would silently
cross the boundary that Phases 4B, 4I, and 4J keep closed.

Before building the general stream/snapshot inbox, the system needs a durable
way to normalize this already-qualified historical evidence, preserve its
source chain, classify mismatches, and replay it idempotently without granting
economic or lifecycle authority.

## Decision

1. Define Phase 4K as durable normalized historical reconciliation evidence
   derived only from an exact Phase 4I authenticated lookup receipt and its
   exact Phase 4C raw-ingress source.
2. Reauthenticate the complete durable source chain before normalization. The
   lookup receipt, account and attempt identities, terminal UNKNOWN event,
   credential/account binding, request permit, fence evidence, raw receipt
   position, raw body digest, and persisted lookup position must agree.
   Normalization re-decodes the retained raw bytes; it does not trust duplicated
   scalar columns as an independent source.
3. Produce exactly one closed disposition for each authenticated lookup
   receipt:
   - `ORDER_OBSERVED_CANDIDATE` for a request-economics and security-identity
     match;
   - `QUARANTINED_ECONOMIC_MISMATCH` for a request-economics mismatch;
   - `QUARANTINED_SECURITY_MISMATCH` for an independently pinned provider
     security-identity mismatch;
   - `INCONCLUSIVE_NOT_VISIBLE` for a qualified 404.
4. A found-order fact preserves provider account, order, asset, and client
   identifiers; local attempt, order, reservation, instrument, and symbol
   identities; status and mismatch fields; request economics; cumulative fill
   quantity and average price; replacement links; and each provider timestamp
   as both its exact source string and nanosecond-preserving normalized value.
5. A not-visible fact has no provider-order identity or order economics. It
   means only that the exact bounded lookup returned the already-qualified
   inconclusive 404 response.
6. Use the authenticated Phase 4I receipt as the observation source identity.
   An exact replay of that source is idempotent. A separate authenticated
   lookup remains a separate historical observation even when its decoded
   values are identical.
7. Do not infer provider ordering from the local append sequence,
   `authenticated_at`, arrival time, or nullable provider `updated_at`.
   Provider timestamps remain observed data, not revision authority.
8. Persist facts in an immutable account-local predecessor chain with a
   lockable terminal head. Source identity, source digests, complete normalized
   payload, append sequence, predecessor digest, and semantic digest are all
   authenticated. Concurrent exact replay produces one fact; conflicting reuse,
   gaps, truncation, rollback, missing sources, and content substitution fail
   closed on write, read, and startup verification.
9. Historical normalization remains valid if the local submission later gains
   authoritative reconciliation evidence. It records what was qualified at the
   time; it does not claim to be the current broker view.
10. Keep all authority properties false. A Phase 4K fact cannot become a
    `BrokerOrderEvent`, establish provider sequence, create an execution or fee,
    apply a bust or correction, resolve `UNKNOWN`, release a reservation,
    mutate lifecycle or ledger state, authorize retry, complete
    reconciliation, change readiness, or cause a broker effect.
11. Phase 4K is not the general normalized inbox. It does not deduplicate
    stream versus snapshot deliveries, qualify trade-update event identities,
    identify fills, interpret corrections, buffer a stream, paginate snapshots,
    converge account views, or apply a reconciliation result.
12. Add no network call, credential resolver, worker, API, trader composition,
    startup authority, or paper-readiness change. The slice operates only on
    already-durable Phase 4I/4C evidence.

## Consequences

The system gains an authenticated, queryable, and replay-safe bridge from one
qualified historical lookup into future reconciliation. Mismatch and
not-visible outcomes are durably visible without being confused with order
state, while complete Order observations retain their precision and provenance
for later comparison.

The general stream/snapshot inbox, stable execution and correction identities,
paginated account views, convergent reconciliation, authoritative application,
paper transport, and the Phase 4 exit matrix remain open. Phase 4K does not
satisfy a paper-trading readiness gate.
