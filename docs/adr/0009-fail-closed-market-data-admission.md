# ADR 0009: fail-closed licensed market-data admission

## Status

Accepted for the provider-neutral Phase 1B boundary. No vendor is admitted yet.

## Context

Phase 1A proved causal normalization, immutable publication, and quarantine with
repository-owned synthetic records. Those facts cannot establish contractual
rights to a vendor feed, production identifier accuracy, historical coverage,
or independent operational approval. The original ingestion workflow also
hardcoded its synthetic source bundle, which could let a future adapter inherit
fixture metadata accidentally.

## Decision

Historical adapters implement a provider-neutral `HistoricalBarSource` port and
return one immutable source bundle. The bundle freezes source identity, adapter
type, entitlement assertion, identifier authority, exact required symbols,
coverage interval, calendar, universe, corporate actions, and raw vendor facts.
Every fact must carry the bundle's source ID; mixed-source inputs fail before an
object or catalog row is written.

Admission is a separate pure decision. An immutable specification pins the
source and required technical checks. An evidence bundle records licensed
status, active entitlement, a digest of the applicable terms, frozen policy
versions, technical evidence digests, executor, and optional independent review.
The deterministic evaluator returns one of:

- `blocked`: licensing, entitlement, source kind, or frozen-profile gates fail;
- `review_pending`: prerequisite and technical gates pass but approval is absent;
- `admitted`: every gate passes and a different operator approves the evidence;
- `rejected`: technical evidence or an independent review rejects the source.

Synthetic and recorded fixtures are permanently ineligible for `admitted`, even
when all reusable technical checks pass. Source profiles cannot self-assert an
admission result. PostgreSQL stores the immutable profile, report, and individual
checks in the same transaction as catalog publication. The browser displays the
result and continues to block paper/live interpretation unless an admitted run
exists. Vendor credentials and contract text are never stored in these tables;
only secret-free metadata and SHA-256 evidence or terms digests are allowed.

Before a proposed production source reaches that generic evaluator, a separate
in-memory prerequisite gate inventories five fixed evidence roles plus one exact
bundle review: production identity/lifecycle, production calendar, authoritative
corporate actions, genuine-raw price semantics and market provenance, production
license/use rights and current entitlement, and independent review. Every opaque
attestation binds the exact source, provider, dataset, feed, frozen profile,
scope, artifact digest, producer, observation time, and explicit half-open
validity interval. The review binds the canonical digest of the complete
attestation bundle and must follow every component; its reviewer must differ
from the gate executor and every evidence producer.

Missing or duplicate roles, synthetic/fixture/research/contract-only evidence,
binding mismatches, rejected evidence, future observations, expired evidence,
an absent or stale review, bundle substitution, or self-approval all fail
closed. The only positive status is `ready_for_admission_evaluation`. It is a
structural inventory result, not evidence authentication or authority: the
caller-supplied `external_authority` classification cannot establish that an
external actor or fact is genuine. The assessment is proof-constructed and
deterministic, exposes historical-source, canonical-data, admission, and trading
effects of `none`, has no `load()` method, and cannot construct
`AdmissionEvidence`, `HistoricalSourceBundle`, or `HistoricalBarSource`.

## Consequences

A licensed adapter can now be added without changing normalization, storage, or
the decision vocabulary. Selecting the vendor, product, identifier authority,
ETF allow-list, legally permitted uses, and licensed evidence remains an explicit
operator decision. Until those inputs exist and pass independent review, Phase 1
is not complete and the trader remains fail-closed. The prerequisite gate adds
no database state and therefore requires no migration; persistence remains a
later decision only after genuine external evidence and a real adapter exist.
