# ADR 0013: Tiingo EOD authorization-gated capture

## Status

Accepted for this bounded Phase 1 slice. Its implementation is limited to an
acquisition boundary exercised with synthetic responses. No live Tiingo request
or capture was performed for this decision. It does not assert license or
retention rights, qualify observed provider bytes, create local correction
revisions, implement `HistoricalBarSource`, admit a source, or enable paper or
live trading.

## Context

ADR 0012 established a strict offline parser using repository-owned synthetic
Tiingo EOD fixtures. The next implementation risk is not parsing; it is allowing
an API credential or successful connectivity probe to become an implicit right
to request and retain exact paid-provider responses. Those are separate facts.
The application needs a mechanically enforced preflight boundary before a
network transport can be invoked or a response can be stored.

Tiingo's reviewed public EOD row contract still does not provide a row-level
publication timestamp, vendor revision number, or historical vintage sequence.
Receipt of a response can prove only when AutoQuantTrader first observed that
delivery. It cannot establish when Tiingo published each row or what an earlier
consumer would have received. One capture also cannot prove correction
behavior; that requires multiple authorized captures and an explicit local
lineage policy.

No approved Tiingo acquisition profile or matching reviewed capture
authorization is presented by this decision. Credentials in `.env` remain
connectivity inputs, not license, storage authorization, admission evidence, or
trading authority.

## Decision

1. Add a separate **authorization-gated capture seam** whose mechanics are
   exercised only with synthetic responses and an injected test transport. The
   production transport must not be invoked unless all preflight checks have
   completed successfully. Bound the symbol request count, each response size,
   and each request's socket-I/O timeout. Treat that timeout honestly as a
   per-request I/O control, not a strict whole-capture wall-clock deadline.
2. Require an approved Tiingo-specific acquisition profile before actual
   operation. The profile records a profile ID, strict approval flag, reviewer
   ID, and UTC review time and freezes the provider and dataset, source ID,
   adapter version, endpoint template, exact `TiingoEodScope`, market
   provenance, identifier/calendar/corporate-action authorities,
   correction-policy identity, and field-schema digest.
3. Separately require a reviewed capture authorization that binds the exact
   normalized `profile_contract_sha256` to a non-placeholder applicable-terms
   digest, effective data bounds, review time, reviewer identity, and strict
   local-retention and research-use permission flags. Parse and structurally
   validate both artifacts before reading `TIINGO_TOKEN`; an API key, access
   probe, offline fixture, or Sharadar authorization cannot substitute for either
   artifact.
4. Evaluate profile approval, the matching authorization, and the requested
   scope before making a request or retaining response bytes. Missing approval,
   a profile-contract-digest mismatch, unreviewed or insufficient rights,
   placeholder digests, out-of-window dates, an expanded symbol set, or a
   changed product contract fail closed without reading the token, calling the
   transport, or writing output.
5. Keep acquisition staged and one-way:

   - repository-owned fixtures qualify the documented response contract;
   - an approved profile freezes one bounded acquisition contract;
   - a matching reviewed authorization permits its intended retention and use;
   - the capture seam requests that exact scope and records actual request and
     receipt times;
   - receipts and manifest bytes are prebuilt, then exact bytes and the
     secret-free manifest are finalized in owner-only staging beneath one fixed,
     gitignored `.local/vendor-snapshots/tiingo-eod` root;
   - an exclusive final-name reservation and descriptor-relative rename make
     publication atomic, so pre-commit faults never expose a partial final
     capture or modify an existing one;
   - a separate offline loader verifies bytes, hashes, schema, coverage,
     calendar binding, and provider semantics;
   - repeated authorized captures are compared by a later local-lineage slice;
   - only still-later admission evaluation may consider the resulting evidence.

6. Keep secrets process-local. The token, credential-bearing URL, response body,
   and terms text must not enter logs, exceptions, manifests, documentation,
   browser responses, or Git. Stored metadata may contain only secret-free scope,
   timing, identity, byte-count, and cryptographic-digest material.
7. Bind the secret-free manifest to the complete acquisition profile and its
   digest, matching
   authorization and terms digests, provider/dataset/schema identities, overall
   request and receipt bounds, and a sorted complete receipt for each requested
   symbol.
8. Treat actual response receipt as the earliest defensible local knowledge time.
   Do not copy receipt time into `vendor_published_at`, derive publication from a
   session date, or invent a vendor revision or sequence number. The capture
   artifact is observation evidence, not yet a canonical market event.
9. Defer repeated-capture correction lineage. This slice makes no claim that an
   unchanged later response is idempotent, that changed economics are a vendor
   correction, or that a missing row is a deletion. The later lineage design
   must preserve first observation, create explicit receipt-time local revisions
   for changed deliveries, and reject incomplete captures without filling,
   carrying forward, or fabricating tombstones.
10. Keep every capture state non-admitting. A synthetically tested seam, an
   approved profile, a matching authorization, a successful future request, and
   a verified future capture each have admission and trading effects of `none`.
   `HistoricalBarSource`, paper submission, and live submission remain
   unreachable.

## Consequences

The code can prove, without contacting Tiingo, that acquisition remains behind
a reviewed-rights boundary and that successful synthetic responses would be
handled through bounded, secret-safe, immutable mechanics. This reduces the
risk of accidental paid-data retention while leaving the external legal and
commercial decision with the designated reviewer.

The normalized profile-contract digest is deliberately independent of JSON
indentation and key presentation; the repository supplies an offline inspection
command to compute it. Reviewer identifiers and timestamps are auditable local
attestations, not cryptographic signatures. Reviewer authentication and any
required separation of duties remain external governance controls.

Normal pre-commit failures and interrupts remove their owned staging and
reservation entries. A process crash may leave a hidden inert staging or lock
entry for manual inspection, but it cannot expose a partially published final
capture. Rename is the commit point; post-commit durability requests are
best-effort so the API cannot report failure while leaving a complete final
capture.

The repository still contains no evidence that an actual Tiingo response was
requested or captured under approved rights. Live payload schema, raw-price
semantics, endpoint provenance, symbol identity, calendar and lifecycle
authority, corporate-action behavior, correction history, and deterministic
replay all remain unqualified. Local revision lineage is deliberately the next
separate implementation concern after authorized capture evidence exists; it is
not inferred from synthetic transport tests.

## References

- [Tiingo end-of-day API](https://www.tiingo.com/documentation/end-of-day)
- [ADR 0009](0009-fail-closed-market-data-admission.md)
- [ADR 0011](0011-daily-first-capture-and-raw-lane-separation.md)
- [ADR 0012](0012-tiingo-eod-offline-first-qualification.md)
