# ADR 0015: Tiingo EOD pinned calendar artifact and operator verification

## Status

Accepted for this bounded Phase 1 slice. The implementation is exercised with
repository-owned synthetic artifacts and injected transports only. It does not
approve a production calendar, make a live request, retain an actual Tiingo
payload, establish vendor publication or revision time, grant admission, or
change trading readiness.

## Context

ADR 0014 verifies a final capture against caller-supplied in-memory exchange
calendars, but the repository has no portable reviewed representation of those
calendars. Supplying calendars only after capture permits post-hoc selection and
does not prove which exact session definitions were frozen before provider
access. It also prevents a safe operator command: substituting the small
synthetic reference calendar would silently assign production authority it does
not possess.

An exchange calendar is more than its first and last session. Those labels
cannot establish that intervening weekends, holidays, emergency closures, or
omitted sessions were considered. The artifact therefore needs an explicit
bounded coverage assertion as well as exact UTC session records.

No real Tiingo capture exists, so this is the least costly point to replace the
capture-manifest schema and adapter version rather than preserve an unsafe
compatibility shape.

## Decision

1. Define a strict, canonical, bounded
   **Tiingo EOD pinned-calendar artifact**. It records artifact and reviewer
   identity, approval, review time, normalized acquisition-profile digest,
   calendar authority, an attested tzdata-version label, exact Tiingo scope, and
   one sorted symbol/calendar record for every scoped symbol and no other symbol.
   Each calendar record freezes its ID, version, venue, timezone, and sorted
   explicit UTC sessions including label, open, close, venue, and regular/half-day kind.
2. Treat the artifact scope as a reviewed completeness assertion. Every stored
   session must fall inside it. Dates inside the inclusive scope that do not
   appear are asserted to be non-session dates; the software does not infer that
   an omission is truly a weekend, holiday, or closure. Human review of the
   selected authority remains necessary. Artifact v1 requires at least one
   explicit in-scope session per symbol, so an all-non-session scope fails closed.
   Explicit UTC sessions are authoritative. The tzdata-version label is bound by
   the artifact digest but is not compared with the host ZoneInfo database;
   ZoneInfo is used only to validate the recorded local session labels.
3. Reject duplicate or unknown JSON fields, non-canonical presentation,
   malformed timezones or sessions, overlapping, unordered, or non-daily session
   spans, non-canonical symbols, empty or lowercase venues, calendar/session
   venue mismatches, out-of-scope sessions, missing symbols, excessive bytes, a
   zero profile digest, and unsupported provider, dataset, or schema identity.
   The artifact does not independently allow-list real-world venue codes. Require:

   `profile.reviewed_at <= artifact.reviewed_at <= capture.requested_at`

   and exact profile digest, scope, and calendar-authority equality.
4. Require the exact canonical artifact bytes at the library and operator
   capture boundaries. Parse and authorize them before reading `TIINGO_TOKEN`,
   invoking transport, or creating output. Add their SHA-256 digest to the
   capture manifest, bump the capture-manifest schema to v2, and bump the
   acquisition adapter identity to v2. Because final capture names commit to the
   complete canonical manifest, the calendar digest also participates in the
   immutable directory identity.
5. Require the same exact artifact bytes during offline verification. Remove
   independently supplied in-memory calendar mappings and authority strings from
   that public boundary. The verifier must match the artifact SHA-256 to the
   manifest, re-authorize it at the first recorded request time, and derive every
   `ExchangeCalendar` only from the reviewed bytes.
6. Add the exact calendar-artifact digest to the verified research snapshot and
   semantic identity and bump the verified-research schema to v2. Carry the
   parsed artifact in the proof and re-derive every calendar binding from it at
   construction. Preserve the non-public proof construction, final
   path/inode/tree revalidation, and all canonical-bar, revision-lineage,
   admission, and production-source refusals.
7. Add a credential-free operator verification command. It accepts one strict
   final capture basename plus stable, single-link, non-symlinked profile,
   authorization, and calendar files in exact owner-only mode `0400` or `0600`.
   It uses the fixed repository capture root, performs no environment loading,
   dependency synchronization, network access, application writes, bytecode
   writes, catalog changes, or admission, and prints only secret-free digests,
   calendar identities, counts, and explicit `admission_effect: none` and
   `trading_effect: none`.
8. Keep the checked-in calendar template non-authorizing and digest-mismatched by
   default. It is a shape guide, not a production calendar generator. Do not
   import an external calendar library or promote the synthetic reference
   calendar until the actual authority, lifecycle rules, tzdata version, and
   complete sessions are selected and reviewed.

## Consequences

A successful capture proves that the software validated exact calendar bytes
carrying the recorded profile and calendar approvals before provider access,
and a successful offline verification proves that those same bytes drive
session interpretation. Presentation-only changes are detectable because the
contract requires canonical exact bytes. Operator verification becomes
reproducible without credentials or network access and cannot create trading
state.

Reviewer identifiers and timestamps remain local attestations rather than
cryptographic signatures. The application validates their ordering and bindings
but cannot prove reviewer identity or the real-world correctness of omitted
dates. Those remain governance responsibilities.

After this slice, the next safe external action is human approval of the exact
profile, rights authorization, and production calendar artifact followed by one
authorized capture and offline verification. Repeated-capture lineage must wait
until at least two complete verified authorized captures exist.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0013](0013-tiingo-eod-authorization-gated-capture.md)
- [ADR 0014](0014-tiingo-eod-offline-capture-verification.md)
- [Pinned-calendar template](../admission/tiingo-eod-pinned-calendar.template.json)
