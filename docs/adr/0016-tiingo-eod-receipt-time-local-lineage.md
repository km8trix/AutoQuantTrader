# ADR 0016: Tiingo EOD receipt-time local delivery lineage

## Status

Accepted for this bounded offline Phase 1 slice. The implementation is exercised
with complete synthetic repeated captures. One authorized provider-backed
capture from 2026-07-17 is a verified baseline only; this decision does not
authorize a second provider request or claim observed real-world correction
behavior. Admission and trading effects remain `none`.

## Context

ADRs 0013-0015 established authorization-gated immutable capture, exact pinned
calendar approval, and descriptor-safe offline verification. The first bounded
operation passed those gates for DIA, IWM, QQQ, and SPY for the completed
2026-01-02 session. Its manifest and four response objects remain owner-only
beneath the ignored local capture root; no provider payload is checked into Git.

Tiingo EOD rows contain a session date but no row-level publication timestamp,
vendor revision number, or historical vintage. A verified capture can prove when
AutoQuantTrader received a delivery, not when Tiingo published it or whether a
changed later delivery is a vendor-designated correction. One capture also cannot
establish repeat behavior. A separate local policy is required before multiple
complete authorized captures can be compared causally.

## Decision

1. Add a pure, network-free **receipt-time local lineage** boundary. It consumes
   an exact tuple of at least two proof-constructed
   `TiingoEodVerifiedResearchSnapshot` values. Each input is revalidated before
   comparison; arbitrary rows, manifests, or unverified capture paths are not
   accepted.
2. Require every snapshot to share the same complete acquisition profile,
   normalized profile digest, correction policy
   `first-observed-local-revisions-v1`, exact canonical pinned-calendar artifact,
   calendar bindings, scope, symbols, and session keys. Capture and snapshot
   semantic digests must be unique. Caller order must be strictly chronological,
   and one capture's request window must begin after the preceding capture has
   completed.
3. Treat `(profile, exact calendar artifact, symbol, session label)` as the local
   logical observation identity. This remains a provider-symbol research key,
   not an immutable internal security identity.
4. Hash row economics independently from delivery metadata. The economics digest
   includes raw-candidate and adjusted OHLCV, cash dividend, split factor, basis
   labels, and daily interval identity using normalized decimal text. It excludes
   request/receipt timestamps, response and capture digests, JSON presentation,
   and response-wide row order. Exact profile and calendar equality are separate
   comparability gates.
5. Preserve one comparison occurrence for every capture/key pair:

   - the first complete occurrence is `initial` and creates local revision 1 at
     its actual response receipt time;
   - an economically identical later occurrence is `unchanged`, remains visible
     as delivery evidence, and reuses the preceding local revision identity;
   - changed economics are `changed` and create the next contiguous local
     revision linked to the immediately preceding local revision;
   - A -> B -> A creates revisions 1, 2, and 3 because the third receipt is new
     causal knowledge, even though its economics match revision 1.

   These are local receipt-time versions. They are never called vendor
   revisions, corrections, publication times, or historical vintages.
6. Reject a missing or extra symbol/session key. Incomplete captures are rejected
   by the existing verifier and again by the lineage boundary. The implementation
   never carries a prior value forward, fills a row, or creates a deletion or
   tombstone.
7. Bind every ordered capture proof, occurrence, effective revision, predecessor,
   exact profile/calendar identity, scope, policy, and schema to deterministic
   SHA-256 identities. The lineage result has no public constructor and
   re-derives all components from its retained verified proofs during validation.
8. Add a credential-free operator command for two or more final capture names.
   It reads one exact owner-only profile, authorization, and calendar artifact
   shared by every capture; v1 does not support artifact rotation. It invokes the
   descriptor-safe verifier separately for each final capture and prints only
   secret-safe capture, scope, and timing metadata, policy and schema identifiers,
   proof digests, counts, a research-only note, and explicit effects of `none`;
   it never prints row values or response bytes. It uses no `.env`, provider
   request, write, catalog transition, admission transition, or trading action.
9. Keep the slice in memory. Do not add files to an immutable capture directory;
   its exact `manifest.json` plus `objects/` tree must remain unchanged. A durable
   derived-lineage artifact requires a later atomic storage contract.
10. Structurally refuse raw or canonical bar conversion, admission evidence, and
    `HistoricalBarSource`. Do not populate `vendor_published_at` or pass these
    local versions through `VendorBarRecord`.

## Verified baseline

The 2026-07-17 offline verifier recorded the following secret-safe proof for the
one authorized provider-backed baseline:

- scope: 2026-01-02, DIA/IWM/QQQ/SPY;
- profile contract: `0979d1a3edf77a46ac41f9702e32cca10a02fb9501ad8ff53d219a892db087ae`;
- calendar artifact: `bad76aac6867f1e47ad8dd3ce7ea4cc9a0c1a2a6b55eb910bb9b4b8818771af1`;
- manifest: `de7314ae32ced92081c2907e5cc892329e03528f810738921c0b0ad924abe846`;
- verified semantic proof:
  `e7174d68f87f45e70aeaf0ce9f8822ae2d9a3fb68ac9aac457bf9c39acbc8664`;
- four observations, four rows, and four one-session calendar bindings;
- admission effect `none`; trading effect `none`.

This baseline is insufficient to construct lineage because the contract requires
at least two complete independently verified captures. A second actual capture
requires a fresh external operator decision and, for v1 lineage, must use the
same exact still-applicable profile, authorization, and calendar artifacts. This
ADR grants no such decision, and v1 does not support artifact rotation.

## Consequences

Synthetic tests can now prove deterministic unchanged, changed, row-local,
reversion, chronology, mismatch, and incomplete-capture behavior without making a
provider request. Presentation-only response changes remain visible as separate
occurrences without masquerading as economic revisions. A response-wide change
to one date does not incorrectly revise every date in that response.

The output still cannot establish execution-safe raw prices, vendor publication
or correction history, immutable security identity, lifecycle or corporate-action
authority, admission, or trading readiness. The next external evidence step is a
fresh operator decision followed by a second complete capture under the same
exact still-applicable artifacts and offline verification. The next
implementation gate is qualification of exact retained raw-candidate fields and
the remaining identity, lifecycle, action, and admission authorities;
`HistoricalBarSource` remains blocked until those gates pass.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0013](0013-tiingo-eod-authorization-gated-capture.md)
- [ADR 0014](0014-tiingo-eod-offline-capture-verification.md)
- [ADR 0015](0015-tiingo-eod-pinned-calendar-and-operator-verification.md)
