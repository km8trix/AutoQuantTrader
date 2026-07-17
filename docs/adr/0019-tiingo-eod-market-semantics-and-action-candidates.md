# ADR 0019: Tiingo EOD market semantics and action-candidate qualification

## Status

Accepted for this bounded, offline Phase 1 contract slice. It authorizes no
provider request and grants no production market-provenance, raw-price,
corporate-action, source, admission, or trading authority.

## Context

ADR 0015 proof-constructs one exact, calendar-bound verified research snapshot.
ADR 0017 proves the exact thirteen retained source fields and their application
routing without promoting their documented roles into vendor semantics. ADR
0018 adds stable security-identity and lifecycle contract mechanics without
qualifying a production identity authority.

The retained contract partitions the source fields into one session-identity
field, five documented-raw-candidate fields, five adjusted-research fields, and
two corporate-action-candidate fields. The acquisition profile's
`market_provenance` and `corporate_action_authority` strings remain frozen policy
labels. Neither label, field spelling, value relationship, nor successful
capture proves how Tiingo formed its prices or that a dividend or split event
occurred.

The next software boundary must freeze structured market-semantics and
action-candidate conventions, bind them to the complete preceding proof chain,
and test their interpretation with repository-owned synthetic cases. It must do
so without inventing production provenance, raw-price authority, action facts,
event absence, or unavailable timestamps.

## Decision

1. Add a separate, pure **market-semantics and action-candidate contract-only
   qualification** boundary. It operates entirely offline and accepts no
   arbitrary provider rows, canonical bars, corporate-action records, security
   masters, or caller-selected capture paths.
2. Bind qualification to one exact proof chain: the ADR 0015 verified snapshot,
   its exact ADR 0017 retained-field qualification, its exact ADR 0018
   identity/lifecycle qualification and canonical identity artifact, and one
   exact canonical market-semantics artifact. Revalidate every proof and require
   matching provider, dataset, source, profile, scope, calendar, snapshot,
   retained-field, identity/lifecycle, and semantics-artifact identities. A
   digest summary, profile label, arbitrary row, or reconstructed proof cannot
   substitute for an input.
3. Define a strict, bounded canonical market-semantics artifact. It binds its
   evidence kind, provider, dataset, non-empty market-semantics evidence-source
   identity distinct from the profile labels and capture transport source,
   normalized profile digest, exact
   identity/lifecycle qualification digest, raw-semantics,
   adjusted-methodology, market-provenance, and action-candidate evidence
   digests, observation and review times, exact DIA/IWM/QQQ/SPY scope, the
   frozen field partition, the two action-candidate conventions, and the five
   synthetic contract cases. Exact canonical bytes participate in artifact and
   qualification identity.
4. Supplement and bind the profile's free-text market-provenance label with a
   structured representation rather than treating the label as structure.
   Freeze the exact product, feed, endpoint, aggregation,
   venue scope, condition scope, session scope, currency, effective-from, and
   optional effective-through boundary. The effective interval is half-open; a
   finite effective-through instant must be strictly later than every selected
   session close. These are contract fields to be checked
   against selected evidence; their presence does not itself establish that the
   evidence is correct or legally usable.
5. Require the exact thirteen-field partition with no overlap, omission, or
   extension:

   - `date`: `session_identity`;
   - `open`, `high`, `low`, `close`, and `volume`:
     `documented_raw_candidate`;
   - `adjOpen`, `adjHigh`, `adjLow`, `adjClose`, and `adjVolume`:
     `adjusted_research`; and
   - `divCash` and `splitFactor`: `corporate_action_candidate`.

   Field names, legacy constraint identifiers, and observed equality or
   inequality never promote a field into canonical `PriceBasis.RAW` or an
   authoritative corporate action.
6. Freeze the candidate conventions independently from observed provider values:

   - `divCash` has neutral decimal string `"0"`, currency `USD`, and orientation
     `positive_cash_per_share_candidate`; a positive finite value is only a
     per-share cash-dividend candidate; and
   - `splitFactor` has neutral decimal string `"1"` and orientation
     `new_shares_per_old_share_candidate`; a positive finite value other than
     one is only a split candidate.

   Both candidates use `row_date_candidate_only`; absence inference is
   `forbidden`; and announcement, publication, payable, and revision fields are
   `not_provided`. Values below one exercise reverse-split orientation. A
   candidate value does not create an event, prove an ex-date, supply an
   unavailable time, or establish the completeness of an action history.
7. Require exactly five repository-owned synthetic contract cases: `neutral`,
   `cash_dividend`, `forward_split`, `reverse_split`, and
   `simultaneous_dividend_forward_split`. The `neutral` case means only that the
   candidate pair equals its frozen neutral values; it does not assert that no
   external event exists. Each case is structurally isolated from retained
   provider observations and trading authority. They test field classification,
   neutral values, amount and ratio orientation, deterministic ordering, and
   simultaneous candidates only.
8. Never infer absence from a neutral candidate or from a missing action record.
   Never infer an event from a non-neutral candidate. Never synthesize
   `announced_at`, `vendor_published_at`, `available_at`, `payable_at`, a vendor
   revision, or a historical vintage from session labels, field values, profile
   review, capture request, or receipt time. Production action completeness and
   event chronology require separately selected, legally usable evidence.
9. Use the pinned calendar and ADR 0018 identity mapping only for their exact
   authorized scope. A session label, venue, stable-ID resolution, candidate
   date role, or synthetic case cannot expand calendar, identity, provenance, or
   action authority.
10. Reject duplicate or unknown JSON fields, non-canonical presentation,
    malformed or non-UTC timestamps, invalid or zero evidence digests, missing
    or extra symbols or fields, partition overlap, altered candidate
    conventions, missing, duplicated, reordered, or provider-bound synthetic
    cases, mismatched profile or identity proofs, impossible chronology,
    self-review, and any attempt to make a synthetic artifact authorizing.
11. Return only an immutable, proof-constructed contract qualification. Bind all
    proof and artifact identities, checks, counts, scope, and explicit effects
    of `none` to a deterministic qualification SHA-256. Do not expose retained
    market values, action-candidate values, evidence content, reviewer identity,
    or private artifact paths in operator output.
12. Keep adjustment-methodology, admission, canonical-bar, corporate-action,
    correction, genuine-raw, historical-source, market-provenance, trading, and
    vendor-publication effects at `none`. Structurally refuse canonical records,
    `CorporateActionRevision`, `HistoricalSourceBundle`, `HistoricalBarSource`,
    admission evidence, or any production-source conversion.
13. Provide a fail-closed, non-authorizing artifact template and a
    credential-free operator command. The command verifies one exact capture,
    derives the ADR 0017 proof, qualifies the exact ADR 0018 identity artifact,
    reads an owner-only canonical market-semantics artifact, and emits only
    secret-safe contract metadata. It reads no `.env`, makes no provider request,
    mutates no capture or catalog, and performs no admission or trading
    transition. Qualification failures use one generic value-free message.

## Consequences

The application can now test the complete retained-field partition, structured
provenance shape, candidate-neutral conventions, forward- and reverse-split
orientation, simultaneous candidates, proof substitution, and authority
separation without contacting Tiingo or inventing production action facts.

No production market-semantics/action-candidate artifact has passed this
boundary. The existing provider-backed baseline has not been
market-semantics/action-qualified, even if its exact snapshot and retained-field
proof are used to exercise the operator path. Genuine unadjusted and
execution-safe prices, actual market provenance, authoritative corporate-action
events and completeness, production identity/lifecycle, source integration,
licensed admission, independent approval, and every paper or live trading gate
remain open.

Passing this contract-only slice cannot grant authority backward to the profile,
capture, snapshot, field proof, identity/lifecycle proof, or any synthetic case.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0008](0008-recorded-point-in-time-admission.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0010](0010-market-data-provider-qualification-routing.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0015](0015-tiingo-eod-pinned-calendar-and-operator-verification.md)
- [ADR 0017](0017-tiingo-eod-exact-retained-field-contract-qualification.md)
- [ADR 0018](0018-tiingo-eod-security-identity-lifecycle-contract.md)
