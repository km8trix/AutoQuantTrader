# ADR 0014: Tiingo EOD offline capture verification

## Status

Accepted for this bounded Phase 1 slice. The verifier is exercised only with
repository-owned synthetic captures. No live Tiingo request is made, no actual
Tiingo payload is included, and this decision does not establish license,
vendor publication time, historical vintage, correction lineage, admission, or
trading authority.

## Context

ADR 0013 added a reviewed-rights boundary and immutable publication mechanics
for a future Tiingo EOD capture. Publication alone is not qualification. A
consumer must prove offline that it opened the intended final capture, that the
manifest and every content-addressed object are intact, that the embedded
profile is the one the caller expects, and that the exact authorization used at
capture time still authorizes that profile.

Tiingo's EOD payload does not include a row-level publication timestamp or
vendor revision sequence. The only defensible knowledge time available to this
slice is the recorded local receipt time. Multiple symbols may also require
different pinned calendar artifacts; silently applying one venue calendar to
all symbols would make session coverage and daily interval bounds ambiguous.

The fixed capture root can contain inert hidden staging or publication-lock
residue after a process crash. Such residue is not a final capture and must
never be traversed, but unrelated residue must not invalidate a separately
published final capture.

## Decision

1. Add a **network-free verifier/loader** for final Tiingo EOD captures. Its
   public boundary accepts a repository root and one strict, single-component
   final capture name. It derives
   `.local/vendor-snapshots/tiingo-eod/<capture-name>` internally and never
   accepts an arbitrary manifest or object path.
2. Traverse the repository, fixed capture root, final directory, object
   directory, manifest, and response objects using descriptor-relative,
   no-follow operations. Require current-user ownership for every fixed-root
   component and final-tree entry, the immutable final directory and file modes
   produced by ADR 0013, regular single-link files, exact expected directory
   entries, bounded reads, and a final name containing the first request
   timestamp plus the complete SHA-256 of the canonical manifest bytes.
   Repository ancestors are path-checked but need not be owner-only. Retain the
   fixed Tiingo-root descriptor and, immediately before success, revalidate the
   fixed root path, selected final name, opened directory identities and
   metadata, exact entry sets, and every file name, inode, and immutable metadata
   record observed during the read.
   Reject symlinks, path escapes,
   `.staging-*` or `.publish-*` targets, missing or extra entries, and renamed
   captures. Ignore unrelated hidden residue beside the selected final capture.
3. Parse the manifest with the existing strict JSON contract, including
   duplicate-key and unknown-field rejection, and require its bytes to equal the
   canonical frozen encoding emitted by the capture seam. Require the embedded
   acquisition profile to equal the caller-supplied expected profile and
   require the manifest's normalized profile digest to match it.
4. Require the caller to supply the exact reviewed authorization bytes. Parse
   and re-authorize those bytes against the expected profile at the manifest's
   first request time. Require their exact SHA-256 digest and applicable-terms
   digest to match the manifest. A self-asserted manifest cannot substitute for
   the external reviewed artifact.
5. Require an exact calendar mapping for every captured symbol and no other
   symbol. Require the caller's expected calendar authority to equal the frozen
   profile authority. Bind each symbol independently to its calendar ID,
   version, venue, timezone, and exact sessions within the capture scope. Do not
   infer that one calendar applies to all symbols.
6. Require the object tree to equal the set of unique content-addressed objects
   referenced by the manifest. Verify every exact byte count and SHA-256 digest
   before parsing. One object may be referenced by multiple receipts when its
   bytes are identical; extra duplicate files are not permitted.
7. Bind each symbol-free Tiingo response to its manifest request/receipt symbol,
   then revalidate it against the frozen Tiingo EOD schema, profile scope,
   numeric bounds, pinned per-symbol calendar, and exact expected session
   coverage. Reject missing, duplicate, out-of-scope, or non-session rows.
   Preserve the receipt time only as local `observed_at`; do not relabel it as
   `vendor_published_at`.
8. Return a deterministic, immutable **verified research snapshot** binding the
   manifest digest, exact authorization digest, expected profile, calendar
   authority, per-symbol calendar digests, rows, and semantic digest. The type
   has no public constructor: its verification factory recomputes the manifest,
   calendar/session, observation/row, and semantic invariants so ordinary
   construction and `dataclasses.replace` cannot forge it. The reusable
   configuration exposes `verify()`, not a structurally compatible
   `HistoricalBarSource.load()`. It must fail closed if asked for canonical raw
   bars, correction/revision lineage, admission evidence, or a
   `HistoricalBarSource`; exposing explicit research rows does not grant those
   downstream authorities.
9. Keep verification credential-free and side-effect-free. It performs no
   provider request, does not read `.env`, does not mutate a capture, and does
   not create catalog, admission, browser, paper, or live-trading state.

## Consequences

The application can detect path substitution, partial or mutable-looking
trees, malformed manifests, authorization/profile substitution, object
corruption, schema drift, calendar drift, and incomplete session coverage
before later research work consumes a retained capture. Verification remains
reproducible because its semantic identity includes every external calendar
binding rather than relying on process defaults.

This proof is deliberately narrow. It establishes internal integrity and the
relationship among supplied local artifacts; it does not prove that receipt
timestamps are independently trustworthy, that Tiingo published a row at any
particular time, that unprefixed OHLCV is execution-safe, or that later
deliveries are vendor corrections. Actual licensed bytes and frozen identity,
lifecycle, corporate-action, and correction authorities remain required.
Repeated-capture local lineage is the next separate concern after at least two
complete authorized captures exist.

The first implementation is a library boundary because the repository does not
yet have a reviewed, portable serialization contract for production pinned
calendars. An operator CLI must not silently substitute the small synthetic
reference calendar; it can be added with that artifact contract in a later
slice.

## References

- [ADR 0002](0002-point-in-time-data-and-storage.md)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0013](0013-tiingo-eod-authorization-gated-capture.md)
