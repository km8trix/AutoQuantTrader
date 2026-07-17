# ADR 0017: Tiingo EOD exact-retained raw-candidate field-contract qualification

## Status

Accepted, implemented, and exercised offline against the existing four-row
verified baseline for this bounded Phase 1 slice. The qualification makes no
provider request and grants no genuine-raw, canonical-bar, corporate-action,
source, admission, trading, or broader-use authority.

## Context

ADR 0012 froze a strict thirteen-field Tiingo EOD contract and classified the
unprefixed OHLCV fields only as documented raw candidates. ADRs 0013-0015 added
reviewed capture, immutable publication, exact calendar binding, and offline
verification. ADR 0016 added local receipt-time lineage for two or more verified
captures without assigning vendor correction semantics.

The verifier already reparses retained response bytes and proves their exact
tree, manifest, schema, coverage, calendar, and receipt bindings. The next
boundary must express that one verified delivery conformed to the frozen field
contract and application routing policy without relabeling that result as proof
that the values are genuinely unadjusted, execution-safe, or authoritative
corporate actions.

One actual verified capture exists for DIA, IWM, QQQ, and SPY for the completed
2026-01-02 session. It contains four responses and four rows. It has now
exercised the value-free exact-field proof, but cannot establish schema stability
over time, adjustment behavior, corporate-action behavior, identity, market
provenance, historical corrections, or wider coverage.

## Decision

1. Add a separate, pure **exact-retained field-contract qualification** boundary.
   It accepts exactly one proof-constructed `TiingoEodVerifiedResearchSnapshot`,
   revalidates that proof, and accepts no arbitrary payload, row, manifest, or
   capture path.
2. Preserve the existing capture identities and frozen field contract. The
   profile must carry the exact `TIINGO_EOD_SCHEMA_SHA256`; the capture schema,
   adapter identity, manifest, response objects, and immutable capture tree are
   not changed. Qualification remains an in-memory derived proof.
3. Independently reparse every retained response and replay each strict source
   field name against its frozen row target. Require the independently parsed
   source value to equal the proof-derived target value, exact exhaustion of the
   thirteen-field contract, every verified symbol/session row, the existing
   scope/calendar/session coverage, and the receipt/response/row bindings.
4. Freeze the application-policy roles independently from observed values:

   - `date` is `session_identity`;
   - `open`, `high`, `low`, `close`, and `volume` are
     `documented_raw_candidate`;
   - `adjOpen`, `adjHigh`, `adjLow`, `adjClose`, and `adjVolume` are
     `adjusted_research`;
   - `divCash` and `splitFactor` are `corporate_action_candidate`.

   These labels are reviewed application policy. Equality, inequality, or any
   other relationship among observed values does not prove those vendor
   semantics.
5. Record only the local checks already supported by the frozen parser and
   verified snapshot: exact keys and routing; duplicate, missing, unknown, and
   invalid-field rejection; finite numeric domains; independent OHLC ordering;
   Decimal parsing without binary-float conversion; scope/calendar/session
   coverage; and receipt/response/row binding. Passing a local constraint proves
   parser and routing conformance, not vendor value correctness.
6. Return an immutable, proof-constructed
   `TiingoEodRetainedFieldQualification` with schema
   `tiingo-eod-retained-field-qualification-v1` and kind
   `exact_retained_field_contract_only`. Bind the input profile, calendar,
   manifest, and snapshot identities; field and role contracts; check IDs;
   scope and request/receipt bounds; counts; explicit effects of `none`; and a
   deterministic qualification SHA-256. The result has no public constructor
   and re-derives its components from the retained snapshot during validation.
7. Expose legacy frozen constraint strings only as
   `source_schema_constraint_id`, including labels with `raw`, `adjusted`,
   or `ex-date` wording. These are frozen source-schema policy identifiers for
   local validation and routing. Neither their wording nor relationships among
   observed values prove canonical `PriceBasis.RAW`, genuine unadjusted data, a
   validated adjustment methodology, authoritative corporate-action or ex-date
   semantics, or execution-safe price authority.
8. Add a credential-free operator command for one final capture name plus the
   exact owner-only profile, authorization, and calendar artifacts. It first
   invokes the descriptor-safe verifier, then derives the field proof. It uses
   no `.env`, provider request, write, catalog transition, admission transition,
   or trading action.
9. Keep operator output value-free. It may include the capture, scope, and timing
   metadata; public profile/calendar/manifest/snapshot, field-contract,
   role-contract, and qualification digests; field bindings, check IDs, counts,
   schema/kind, a research-only note, and explicit effects of `none`. It must not
   print response values or bytes, response-object or per-row/per-field value
   digests, value ranges or equality indicators, credentials, terms, reviewer
   identities, or private artifact paths.
10. Structurally refuse raw or canonical bar conversion, corporate-action
    conversion, admission evidence, and `HistoricalBarSource`. Pinned-calendar
    venue bindings define session interpretation only; they are not evidence of
    the venue or market composition from which Tiingo formed OHLCV. A provider
    symbol remains an alias rather than an immutable internal security identity.

## Existing baseline result

The credential-free command successfully qualified the existing verified
baseline. The value-free result records:

- schema: `tiingo-eod-retained-field-qualification-v1`;
- kind: `exact_retained_field_contract_only`;
- four observations, four rows, one session, thirteen frozen fields, and
  fifty-two field occurrences;
- field-contract SHA-256:
  `d1154dece587151bdd71823b92239d111db4e1ec7d25dceb3eb381a9d551402f`;
- role-contract SHA-256:
  `ea629f8f14479076c6b46807b6ad56735b9b907512b0a4c4d10ef43ddf872a5b`;
- qualification SHA-256:
  `a9634c5dec1e1bb5bf9de0690dc45f780c22de5862dcf5c338f425b31fe3dc1b`;
- admission, corporate-action, raw-execution, and trading effects of `none`.

That bounded input can prove only that those exact four rows conformed to the
frozen shape, local numeric and OHLC constraints, and source-to-row routing. It
cannot prove that unprefixed OHLCV is genuinely unadjusted or execution-safe;
that adjusted fields implement a validated methodology; that dividend or split
fields are authoritative events; that values are correct; that the field shape
is stable on other dates; or that identity, lifecycle, publication, vintage,
correction, licensing, admission, or trading gates have passed.

## Consequences

The application now has a stable distinction between synthetic contract tests,
verified retained bytes, and a value-free exact-field proof. The proof can be
used to plan later qualification work without exposing retained provider values
or silently promoting a research observation into the canonical data plane.

This boundary does not depend on a second capture or on local lineage. Those are
separate evidence concerns. The remaining raw-data gate requires independent
evidence that the documented candidates are genuinely unadjusted and
execution-safe, plus validated market provenance, immutable security identity,
lifecycle and corporate-action authority, source integration, licensed
admission, and independent approval.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0013](0013-tiingo-eod-authorization-gated-capture.md)
- [ADR 0014](0014-tiingo-eod-offline-capture-verification.md)
- [ADR 0015](0015-tiingo-eod-pinned-calendar-and-operator-verification.md)
- [ADR 0016](0016-tiingo-eod-receipt-time-local-lineage.md)
