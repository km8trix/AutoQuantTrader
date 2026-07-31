# ADR 0076: durable authenticated account-activity traversals

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4AD defines a bounded raw-first ascending FILL-activity traversal, but it
does not resolve credentials, admit requests, call Alpaca, or persist a
restart-safe cursor. Running a whole traversal in process memory would leave an
unsafe crash ambiguity: once a page is prepared, admitted, sent, or durably
received, a restarted process cannot safely decide that sending it again is
the same operation.

The existing account coordinator, Phase 4G provider-account binding, Phase 4D
request permits, and Phase 4C raw ingress journal supply the source evidence
needed for a narrower runtime. They do not alone prove which exact Phase 4AD
cursor and predecessor may be used next.

## Decision

1. Define Phase 4AE as the
   `phase4ae-authenticated-durable-account-activity-page-v1` boundary. A public
   operation advances at most one Phase 4AD page; it never hides an automatic
   pagination loop.
2. Persist the immutable traversal plan and an exact single-use page
   preparation before credential resolution, request-budget admission, or
   transport. Derive request and delivery idempotency identities from that
   preparation rather than accepting caller-selected identities.
3. Require the exact terminal Phase 4G provider-account binding and one stable
   account fence around transport and durable commit. This authenticates
   historical account identity continuity, not current balance, status, or
   readiness.
4. Consume a fresh reconciliation-purpose Phase 4D permit for every page.
   Reauthenticate its demand, policy, freshness, and durable source position
   before transport; an already issued demand cannot be resent.
5. Restrict transport to the frozen Phase 4AD
   `GET /v2/account/activities` FILL profile using
   `strict-httpx-alpaca-paper-account-activity-page` version `1.0.0`. Preserve
   TLS verification, disable redirects and ambient proxy behavior, bound each
   HTTP phase, reject compression, and retain no more than the Phase 4C
   one-mebibyte response ceiling.
6. Resolve paper credentials only inside the page operation. Retain only a
   secret-free resolution receipt, expose authentication headers solely to the
   restricted transport, and close and zero owned mutable secret buffers on
   every exit path.
7. Commit representable response metadata and exact bytes through Phase 4C
   before status, media type, request ID, UTF-8, JSON, or Phase 4AD decoding
   qualification. A typed failure can leave diagnostic raw evidence but cannot
   create an authenticated page.
8. Record each typed page under the SQL account lock with a
   transaction-internal current-fence check. Cross-bind its exact plan,
   preparation, predecessor, account binding, pre/post identity receipts,
   credential receipt, demand, permit and freshness proof, stable fence,
   transport request and response, raw ingress receipt, decoded Phase 4AD page,
   and commit fence.
9. Persist plans, immutable preparations, page receipts, and traversal heads.
   Page numbers and raw ingress sequences are contiguous in their respective
   chains; later pages bind the exact preceding runtime receipt, persisted page
   digest, and exact unmodified cursor. Each preparation, permit, and raw
   receipt is single-use.
10. Distinguish active, stalled, cursor-exhausted-unisolated, and
    bounded-truncated heads. Cursor exhaustion ends only this non-isolated walk;
    bounded truncation retains incomplete evidence. Neither is provider history
    completeness.
11. Fail closed after a crash once preparation is durable. A later caller
    encountering that unresolved claim cannot resolve credentials, acquire
    another permit, or call transport. A new capture identity is required until
    a separately reviewed recovery policy can prove another action safe.
12. Reconstruct every durable page from its original plan, preparation,
    binding, lease, permit, raw ingress bytes, and predecessor before returning
    a prefix or traversal state. Gaps, forks, substitutions, head rollback,
    orphan facts, altered raw bytes, and resealed canonical payloads fail read
    and startup integrity checks.
13. Keep canonical execution/revision identity, deduplication, bust or
    correction application, complete account history, convergence,
    reconciliation completion, readiness, reservation release, resubmission,
    and every broker or trading authority false.

## Consequences

The repository can resume only from an exactly authenticated completed prefix
and can prove the one next Phase 4AD page that was prepared. It deliberately
loses liveness after an ambiguous crash rather than risk a duplicate provider
call or a traversal assembled from overlapping broker views.

Phase 4AE does not compare two captures, qualify a complete activity history,
identify a canonical execution or correction, deduplicate REST and stream
events, apply inbox or ledger facts, establish reconciliation, or open paper
startup. Those remain separate phases.
