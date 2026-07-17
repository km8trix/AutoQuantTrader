# ADR 0018: Tiingo EOD security-identity and lifecycle contract-only qualification

## Status

Accepted for this bounded, offline Phase 1 contract slice. It authorizes no
provider request and does not assert that a production identifier or lifecycle
authority artifact has passed. Every result remains non-canonical,
non-admitting, and non-trading.

## Context

ADR 0017 proves that one exact verified Tiingo EOD delivery conformed to the
frozen retained-field and application-routing contracts. It deliberately leaves
each Tiingo ticker as a provider alias rather than an immutable internal security
identity. The acquisition profile's `identifier_authority` value is only a
frozen policy label; repeating that string in another object would not establish
an authoritative mapping.

The initial qualification scope is exactly DIA, IWM, QQQ, and SPY. Phase 1 also
requires a separate, non-trade-enabled lifecycle corpus containing a ticker
change and a delisted security. Those cases must exercise stable identity,
effective-dated aliases, knowledge time, and tradability without silently
expanding the four-symbol trading scope.

The pinned calendar establishes how captured session labels map to exact UTC
session intervals. A venue string or lifecycle instant does not itself establish
calendar authority, and the capture-scoped calendar cannot be silently extended
to cover unrelated lifecycle dates. Production identity and lifecycle facts
therefore remain independent evidence concerns.

## Decision

1. Add a separate, pure **security-identity and lifecycle contract-only
   qualification** boundary. It is offline and accepts no arbitrary provider
   rows, canonical bars, security master, or capture paths.
2. Define a strict, bounded, canonical identity/lifecycle artifact. It binds its
   evidence kind, provider, dataset, source ID, normalized acquisition-profile
   digest, identifier-authority label and version, observation and review times,
   exact scope, stable internal security records, and effective-dated provider
   alias and tradability facts. Exact canonical bytes participate in the
   artifact identity.
3. Require the trade-enabled portion of the artifact to contain exactly DIA,
   IWM, QQQ, and SPY, with no missing or additional symbol. At each scoped
   pinned session and causal `as_of`, one provider-symbol/venue fact must
   continuously resolve from the exact session open through the exact session
   close to one opaque internal security ID. The close instant is the downstream
   daily-bar normalization instant. Require the exact same full-session
   continuity for all four universe memberships. Reject unknown, ambiguous,
   overlapping, conflicting, gapped, or non-causally-visible facts.
4. Keep the lifecycle corpus structurally separate and non-trade-enabled. The
   synthetic contract corpus must include:

   - a ticker change whose old and new effective-dated aliases resolve to one
     stable internal security ID; and
   - a delisted security whose effective-dated lifecycle becomes non-tradable.

   The three lifecycle symbols are pairwise distinct, own exactly two lifecycle
   security IDs, and cannot alias any of the four trade-security IDs. The
   bounded corpus contains exactly six security IDs. Neither case can expand
   the DIA/IWM/QQQ/SPY allow-list or produce a trade-enabled source record.
5. Preserve valid time and knowledge time separately. Identifier or lifecycle
   evidence becomes usable no earlier than its independently recorded
   observation time. Do not backdate knowledge to a session label, effective
   instant, profile review, or capture receipt.
6. Bind qualification to one exact proof-constructed verified research snapshot
   and its exact ADR 0017 retained-field qualification. Revalidate both proofs
   and require matching profile, source, scope, snapshot, retained-field,
   calendar-artifact, and identity/lifecycle-artifact identities. A caller cannot
   substitute summaries, digests, arbitrary rows, or a profile authority string.
7. Use the pinned calendar only for the sessions its exact artifact authorizes.
   Require venue agreement for scoped mappings, but do not treat a venue label,
   effective lifecycle instant, or identifier artifact as calendar authority.
   Lifecycle dates outside the pinned scope require a separately reviewed exact
   calendar authority before production qualification; synthetic calendar facts
   may test the software contract only.
8. Reject duplicate or unknown JSON fields, non-canonical presentation,
   malformed or non-UTC timestamps, invalid digests, missing or extra scope,
   unknown security IDs, duplicate mappings, overlapping effective intervals,
   impossible chronology, non-exclusive ticker-change boundaries, any
   post-delisting tradability interval, cross-venue or cross-corpus aliasing,
   session-coverage gaps, and any attempt to mark the synthetic lifecycle
   corpus as trade-enabled.
9. Return only an immutable, proof-constructed contract qualification. Bind all
   input identities, checks, counts, scope, and explicit effects of `none` to a
   deterministic qualification identity. Do not expose retained market values
   or private artifact contents in operator output.
10. Keep production-identity, raw-execution, canonical-bar, corporate-action,
    historical-source, admission, and trading effects at `none`. Structurally
    refuse conversion to a production `SecurityMaster`, canonical records,
    corporate actions, admission evidence, a `HistoricalSourceBundle`, or
    `HistoricalBarSource`.
11. Provide a fail-closed, non-authorizing artifact template and a
    credential-free operator command. The command verifies one exact capture,
    derives the ADR 0017 proof, reads an owner-only canonical identity/lifecycle
    artifact, and emits only secret-safe contract metadata. It will read no
    `.env`, make no provider request, mutate no capture or catalog, and perform no
    admission or trading transition. Qualification failures use one generic
    value-free message so malformed private artifact content cannot enter
    operator output.

## Consequences

The application can test exact scope, causal identifier resolution, ticker-change
continuity, delisting behavior, artifact substitution, and authority separation
without contacting Tiingo or inventing production mappings. The checked-in
lifecycle corpus and template remain synthetic software-contract inputs.

No production identity/lifecycle artifact has passed this boundary, and the
existing provider-backed baseline has not been identity-qualified by this ADR.
Real identity and lifecycle correctness still requires a selected authority,
legally usable exact evidence, causal observation times, applicable calendar
authority, and independent review.

Genuine unadjusted price semantics, price-source market provenance,
corporate-action authority, production source integration, licensed admission,
independent admission approval, and all paper or live trading gates remain open.
Passing this contract-only slice cannot grant authority backward to the capture,
snapshot, retained-field proof, or profile.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0008](0008-recorded-point-in-time-admission.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0010](0010-market-data-provider-qualification-routing.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0015](0015-tiingo-eod-pinned-calendar-and-operator-verification.md)
- [ADR 0017](0017-tiingo-eod-exact-retained-field-contract-qualification.md)
