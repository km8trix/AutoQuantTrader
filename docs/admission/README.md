# Market-data admission

The admission framework and provider qualification order are implemented, but
no external market-data product is admitted. A synthetic report, successful
access probe, or bounded research capture may prove reusable software,
connectivity, and local-integrity contracts; none can satisfy the Phase 1 vendor
gate by itself.

## Current candidate routing

- Sharadar SFP is the first immutable daily research-capture adapter. Its OHLCV
  is split/stock-dividend adjusted and only `closeunadj` is directly raw, so it
  is structurally blocked from the canonical raw execution lane.
- Tiingo EOD is independent validation and the next raw-daily qualification
  candidate. Its parser, authorization-gated acquisition, final-capture
  verifier, local-lineage mechanics, exact-retained field-contract boundary,
  and offline security-identity/lifecycle contract boundary are implemented.
  One bounded provider-backed capture has also been retained and verified as a
  research-only baseline, then passed through the exact-
  retained field-contract boundary with a value-free proof. Genuine-raw
  semantics, real identity/lifecycle authority, a production source, and
  admission remain blocked. No production identity/lifecycle artifact has
  passed. Its IEX history is single-venue and is never substituted for SIP.
- Massive raw SIP trades and quotes remain the deferred intraday and execution-
  evidence candidates; vendor minute aggregates are reconciliation input only.

The qualification allow-list is DIA, IWM, QQQ, and SPY, plus a separate
non-trade-enabled ticker-change/delisting corpus. See
[ADR 0010](../adr/0010-market-data-provider-qualification-routing.md),
[ADR 0011](../adr/0011-daily-first-capture-and-raw-lane-separation.md),
[ADR 0012](../adr/0012-tiingo-eod-offline-first-qualification.md),
[ADR 0013](../adr/0013-tiingo-eod-authorization-gated-capture.md),
[ADR 0014](../adr/0014-tiingo-eod-offline-capture-verification.md),
[ADR 0015](../adr/0015-tiingo-eod-pinned-calendar-and-operator-verification.md),
[ADR 0016](../adr/0016-tiingo-eod-receipt-time-local-lineage.md),
[ADR 0017](../adr/0017-tiingo-eod-exact-retained-field-contract-qualification.md), and
[ADR 0018](../adr/0018-tiingo-eod-security-identity-lifecycle-contract.md).

## Secret-safe access probe

Run one bounded authenticated read per candidate with:

    make market-data-probe DATE=2026-07-14 SYMBOL=SPY

The probe reads TIINGO_TOKEN, NASDAQ_DATA_LINK_API_KEY, and MASSIVE_API_KEY from
an owner-only gitignored .env using non-interpolating dotenv parsing. It rejects
symlinks and group/other-readable files and never invokes a shell. It never
prints a credential, response body, or credential-bearing URL. Its JSON contains
only the provider, configured flag, access classification, HTTP status, row
count, sample, and an explicit admission effect of none.

Massive REST access uses MASSIVE_API_KEY. Flat-file S3 access is a distinct
credential pair: MASSIVE_ACCESS_KEY_ID and MASSIVE_S3_SECRET_ACCESS_KEY. Never
infer that an ambiguously named MASSIVE_API_SECRET is the S3 secret.

## Current access evidence

The secret-free probe run on 2026-07-16 used the completed 2026-07-14 session:

| Candidate product | Sample | Result | Admission effect |
|---|---|---|---|
| Massive minute aggregates | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row | None; aggregate access does not preserve the raw correction timeline |
| Massive raw trades | SPY | HTTP 403, not entitled | Blocks the one-minute primary lane |
| Massive historical quotes | SPY | HTTP 403, not entitled | Blocks the quote/execution-evidence lane |
| Sharadar SFP | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row for each | None; product access and daily coverage only |
| Tiingo EOD | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row for each | None; product access and daily coverage only |

No response body, credential, or credential-bearing URL was retained by the
probe. ADR 0011 selected the daily-first implementation while retaining the
one-minute lane for later entitlement. Daily access must not be relabeled as
one-minute readiness, and adjusted SFP OHLCV must not be relabeled as raw.

## Immutable Sharadar research capture

Exact provider pages may be retained only after a designated reviewer confirms
that the applicable terms permit both local snapshot storage and research use.
Start from the
[fail-closed authorization template](sharadar-sfp-capture-authorization.template.json),
replace the placeholder authorization/reviewer IDs and zero terms digest, set
the effective dates, and change both permission flags to `true` only when that
review is complete. The `terms_sha256` value is the SHA-256 digest of the exact
terms that were reviewed; the terms text and all credentials remain outside the
artifact.

Capture a completed bounded range (maximum 366 inclusive dates) with the
reviewed artifact:

    make sharadar-sfp-capture START_DATE=2026-07-14 AUTHORIZATION=path/to/reviewed-authorization.json

The command reads only `NASDAQ_DATA_LINK_API_KEY` from the owner-only `.env`,
validates the authorization before requesting or retaining an exact page,
follows a bounded cursor chain, and writes exact response pages plus a
secret-free manifest only under the fixed, ignored
`.local/vendor-snapshots/sharadar-sfp` root. The command has no arbitrary output
destination. Objects are created exclusively with owner-only read permissions.

The manifest binds the reviewed authorization and terms digests, exact response
bytes, cursor lineage, and the observed response-column schema digest. The
offline reader verifies paths, permissions, sizes, hashes, cursor completeness,
schema, allow-list, duplicate primary keys, and every required symbol/session.
It then binds the capture digest to the pinned calendar ID, version, timezone,
and exact session bounds so a change in derived daily timestamps changes the
semantic dataset digest. SFP's adjusted OHLCV is preserved only as explicit
research fields and never enters canonical raw bars. Capture output is
research-only and has admission and trading effects of `none`.

## Tiingo offline qualification boundary

Tiingo's official EOD contract distinguishes unprefixed OHLCV from adjusted
fields and exposes split and cash-dividend fields. The implemented offline
qualifier models that contract using repository-owned synthetic fixtures only.
It proves local parser behavior, raw-candidate basis separation, coverage rules,
causal receipt-time handling, and deterministic output. Its results are
permanently `synthetic_contract_only` and cannot emit admission evidence or
canonical execution bars. It cannot prove a live schema, entitlement,
provenance, historical revision behavior, or licensed use.

The reviewed public documentation does not supply the full publication and
historical-vintage timeline needed to treat a historical row as known on its
session date. Any authorized capture therefore uses its actual receipt time as
the earliest knowledge evidence. ADR 0016 creates explicit local versions only
when complete independently verified repeated captures differ. Neither capture
nor lineage may invent pre-capture vintages.

No Tiingo payload may be retained until an approved provider-specific
acquisition profile freezes the exact scope and a matching authorization
confirms local storage and research rights and binds the reviewed terms digest,
and an exact canonical pinned-calendar artifact is approved against that
profile.
Before a production `HistoricalBarSource` is implemented, the exact
endpoint/product, venue or market provenance, identifier mapping, calendar,
lifecycle, corporate-action authority, and correction policy must be frozen and
validated against authorized bytes. The existing Sharadar authorization
template does not authorize Tiingo capture.

See the official
[Tiingo end-of-day API](https://www.tiingo.com/documentation/end-of-day) and
[ADR 0012](../adr/0012-tiingo-eod-offline-first-qualification.md). Offline
synthetic qualification and every authorized capture have admission and trading
effects of `none`.

## Tiingo authorization-gated capture seam

ADR 0013 adds acquisition mechanics only. Preflight, bounded request count and
response size, finite per-request socket-I/O timeout,
request/receipt timing, secret-safe metadata, and immutable-output behavior are
tested with repository-owned synthetic responses and an injected transport. One
bounded provider-backed operation has also retained and verified actual response
bytes. That operation does not establish admission, trading, publication-time,
historical-vintage, vendor-correction, or broader-scope authority.

Every actual operation remains blocked until a human-approved, Tiingo-specific profile
records its profile ID, reviewer, review time, and approval flag and freezes the
exact product, endpoint, source and adapter, allow-list, requested dates, market
provenance, authority bindings, and correction-policy identity. A separate
matching authorization must bind that normalized profile-contract digest to the
reviewed terms digest, effective dates, reviewer, and
explicit local-retention and research-use permission flags. Neither artifact
contains credentials or terms text. A separate approved calendar artifact must
bind the same profile digest, authority, and exact scope before capture. An API
token, a successful probe, an offline
fixture, or the Sharadar capture authorization is not a substitute. A failed
profile, rights, or calendar preflight must occur before `TIINGO_TOKEN` is read,
before transport, and before any output.

The secret-free manifest contract binds the full acquisition profile and
normalized contract digest, matching authorization and terms digests,
the exact pinned-calendar artifact digest, provider/dataset/schema identities,
overall request and receipt bounds, and sorted complete receipts for every
requested symbol. That manifest shape is synthetic-tested and the first actual
manifest remains beneath the ignored owner-only local capture root; no provider
payload or manifest is checked into Git. The offline verifier is exercised
against both synthetic captures and that actual retained baseline. Canonical
conversion and source integration remain later stages.

The staged flow is:

1. Qualify the documented response contract using repository-owned fixtures.
2. Obtain approval of the exact Tiingo acquisition profile, a separate matching
   authorization for the intended storage and research rights, and an exact
   canonical pinned-calendar artifact reviewed against that profile.
3. Only then perform one bounded request scope and immutably retain exact bytes
   plus secret-free request, receipt, size, identity, and digest evidence.
4. Verify the capture offline against its manifest, schema, coverage, pinned
   authorities, and the same exact calendar artifact without making another
   request.
5. Derive the value-free exact-retained field-contract proof from one verified
   capture while keeping every unprefixed field a documented raw candidate.
6. Qualify the offline identity/lifecycle contract against one exact snapshot,
   its exact ADR 0017 proof, and canonical artifact bytes. This software step
   does not qualify a production authority.
7. Compare multiple complete authorized captures through the implemented
   receipt-time local delivery-lineage boundary.
8. Only after independent genuine-raw, provenance, real identity/lifecycle, and
   corporate-action authority gates may a production `HistoricalBarSource` be
   implemented.
9. Only after source integration and the licensed admission gates may data
   enter canonical or trading use.

Steps 1-4 have completed once for the exact approved 2026-01-02 scope covering
DIA, IWM, QQQ, and SPY. Step 5 has completed for its four rows and fifty-two
field occurrences with a value-free proof and all effects `none`. Step 6 is
implemented only as a contract boundary with a separate synthetic
ticker-change/delisting corpus; no production identity/lifecycle artifact has
passed and the actual baseline has not been identity-qualified. Step 7 is
implemented and synthetic-tested, but only one actual capture exists, so no real
repeated-delivery comparison can yet be made.
Receipt time is never written into `vendor_published_at`, changed rows are not
called vendor corrections, and missing rows reject the lineage instead of
becoming deletions or tombstones. Every stage listed here has admission and
trading effects of `none` until the independent admission and deployment gates
explicitly say otherwise. See
[ADR 0013](../adr/0013-tiingo-eod-authorization-gated-capture.md),
[ADR 0014](../adr/0014-tiingo-eod-offline-capture-verification.md),
[ADR 0015](../adr/0015-tiingo-eod-pinned-calendar-and-operator-verification.md),
[ADR 0016](../adr/0016-tiingo-eod-receipt-time-local-lineage.md),
[ADR 0017](../adr/0017-tiingo-eod-exact-retained-field-contract-qualification.md), and
[ADR 0018](../adr/0018-tiingo-eod-security-identity-lifecycle-contract.md).

Start from the fail-closed
[acquisition-profile template](tiingo-eod-acquisition-profile.template.json),
[capture-authorization template](tiingo-eod-capture-authorization.template.json),
and [pinned-calendar template](tiingo-eod-pinned-calendar.template.json).
Copy them to a gitignored location, make each file owner-only (`chmod 600`),
replace every placeholder, and enable approval or permission fields only after
the applicable review. Produce the profile's normalized contract digest
deterministically with:

```bash
make tiingo-eod-profile-inspect PROFILE=path/to/reviewed-profile.json
```

The inspection command reads no credential and makes no request. Put the printed
`profile_contract_sha256` in an authorization and calendar artifact reviewed
no earlier than the profile. The profile digest covers the normalized strict
contract, not JSON indentation or other presentation bytes. Calendar bytes,
by contrast, must use their canonical frozen encoding because the manifest
binds their exact SHA-256. The checked-in authorization has both permissions
disabled and zero placeholder digests, while the checked-in calendar is
unapproved and digest-mismatched. Neither can be used accidentally.
Every venue, timezone, session label, open, close, and kind in the calendar
template is illustrative and must be reviewed and replaced where applicable,
even when it is not prefixed with `replace-`.
After the external review is complete, the bounded operator entry point is:

```bash
make tiingo-eod-capture START_DATE=2026-07-14 \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

`END_DATE` is optional and defaults to `START_DATE`; the profile scope must
match the command exactly. The target defaults to all four Phase 1 symbols;
optional `SYMBOLS="DIA SPY"`-style subsets must exactly match the reviewed
profile and calendar. The command does not qualify, admit, normalize, or trade
the captured data.

Every existing fixed capture-root component beneath the repository must be
owner-only; higher repository and OS ancestors are traversed without following
symlinks but need not be owner-only. After every response is validated, receipts
and manifest bytes are prebuilt, written beneath an owner-only hidden staging
directory, durably finalized, and atomically renamed under an exclusive
final-name reservation. Pre-commit faults and interrupts do not publish a final
capture or alter an existing one. A process crash can leave a hidden inert
staging or reservation entry for manual inspection, but never a partially
published final capture.

The timeout applies to socket I/O for each symbol request and is not a strict
deadline for the complete capture. Run the command under an external supervisor
when policy requires a hard whole-process deadline.

Reviewer IDs and timestamps are auditable local attestations rather than
cryptographic signatures. Reviewer authentication and any required separation
of duties remain part of the external review process; the capture code enforces
the profile and calendar approval flags, causal review order and profile
bindings, plus the authorization effective dates and rights flags.

## Tiingo offline final-capture verification

ADR 0014 implements the network-free verification mechanics for step 4. The
loader accepts a repository root and one strict final capture name, derives the
fixed `.local/vendor-snapshots/tiingo-eod` path internally, and rejects arbitrary
paths, symlinks, staging or publication-lock targets, renamed captures, wrong
ownership or immutable modes, and missing or extra tree entries. The final name
contains the first request timestamp plus the full SHA-256 of the canonical
manifest. The loader retains its fixed-root descriptor and finally revalidates
the fixed path, selected name-to-inode binding, directory metadata, file
identities, and exact entry sets. Unrelated hidden crash residue beside the
selected final capture is inert and ignored.

The caller must supply the exact reviewed authorization bytes, expected
acquisition profile, and exact canonical pinned-calendar bytes. The loader
re-authorizes both reviewed artifacts at the recorded first request time,
verifies their exact digests, derives every calendar from the portable
artifact, checks every unique content-addressed object, reparses each response,
and requires exact per-symbol session coverage. A shared object is valid only
when multiple receipts genuinely reference the same exact bytes.

The result is a deterministic verified research snapshot. Receipt time is
preserved as local `observed_at`; it is never called vendor publication time.
Requests for revision lineage, canonical raw bars, admission evidence, or a
production source fail closed. The result cannot be constructed through its
public API or altered with `dataclasses.replace`; the verifier recomputes its
manifest, calendar/session, observation/row, and semantic proof. The reusable
wrapper exposes `verify()` rather than the production source protocol's
`load()`. The implementation is synthetic-tested and has verified the one
bounded actual Tiingo response set described below.

The credential-free operator entry point is:

```bash
make tiingo-eod-verify \
  CAPTURE=final-capture-basename \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

It reads no `.env`, credential, or network resource; performs no writes,
catalog changes, or admission; and prints only secret-free proof digests,
calendar identities, and counts. The synthetic reference calendar is never
substituted implicitly.

## First authorized Tiingo EOD capture proof (2026-07-17)

One exact reviewed scope was captured and verified offline. The retained
manifest and response objects remain owner-only beneath the ignored local tree;
none is checked into Git. The publishable proof is:

- capture: `20260717T040624825351Z-de7314ae32ced92081c2907e5cc892329e03528f810738921c0b0ad924abe846`;
- scope: 2026-01-02, DIA/IWM/QQQ/SPY;
- profile contract: `0979d1a3edf77a46ac41f9702e32cca10a02fb9501ad8ff53d219a892db087ae`;
- authorization artifact: `bac0779c5212ed7f6009e3a2c7803e51bcd3b371c5b63db6ffff2a7f6eb1a7fe`;
- calendar artifact: `bad76aac6867f1e47ad8dd3ce7ea4cc9a0c1a2a6b55eb910bb9b4b8818771af1`;
- manifest: `de7314ae32ced92081c2907e5cc892329e03528f810738921c0b0ad924abe846`;
- verified semantic proof:
  `e7174d68f87f45e70aeaf0ce9f8822ae2d9a3fb68ac9aac457bf9c39acbc8664`;
- schema `tiingo-eod-verified-research-v2`, four observations, four rows, and
  four one-session calendar bindings;
- admission effect `none`; trading effect `none`.

This record deliberately excludes response values and bytes, credentials,
credential-bearing URLs, terms text and digest, reviewer identity, and private
artifact contents or paths. Approval was specific to the recorded scope and
does not authorize arbitrary reruns, broader dates, or another product.

## Tiingo exact-retained field-contract qualification

ADR 0017 implements a proof-constructed, in-memory field qualification for one
verified capture:

```bash
make tiingo-eod-fields-qualify \
  CAPTURE=final-capture-basename \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The command first performs the complete descriptor-safe offline verification,
then independently reparses each retained response and replays each strict
source field name against its frozen row target. It proves exact field presence,
local numeric and OHLC constraints, and source-to-row routing under four
application-policy roles:

- `date`: `session_identity`;
- unprefixed OHLCV: `documented_raw_candidate`;
- adjusted OHLCV: `adjusted_research`;
- `divCash` and `splitFactor`: `corporate_action_candidate`.

The CLI emits the legacy frozen constraint strings under
`source_schema_constraint_id`. Their `raw`, `adjusted`, and `ex-date`
wording is source-schema policy for local validation and routing; it does not
grant canonical `PriceBasis.RAW`, execution-safe authority, a validated
adjustment methodology, or authoritative corporate-action or ex-date semantics.
Observed equality or difference between field groups does not prove those
semantics. Calendar venues bind session interpretation only and do not prove
Tiingo's price-source market provenance.

The command runs offline/frozen without `.env`, network, bytecode writes,
catalog changes, admission, or trading effects. It prints only value-free
capture/scope/timing metadata, field names and roles, check IDs, counts, public
proof and contract digests, schema/kind, a research-only note, and explicit
effects of `none`. It never prints response values or bytes, response-object or
per-value digests, value ranges or equality indicators, terms, reviewer IDs, or
private paths.

The known baseline has completed this boundary for four observations, four
rows, one session, thirteen fields, and fifty-two field occurrences. Its
value-free identities are:

- field-contract SHA-256:
  `d1154dece587151bdd71823b92239d111db4e1ec7d25dceb3eb381a9d551402f`;
- role-contract SHA-256:
  `ea629f8f14479076c6b46807b6ad56735b9b907512b0a4c4d10ef43ddf872a5b`;
- qualification SHA-256:
  `a9634c5dec1e1bb5bf9de0690dc45f780c22de5862dcf5c338f425b31fe3dc1b`.

The recorded schema is `tiingo-eod-retained-field-qualification-v1`, the kind
remains `exact_retained_field_contract_only`, and admission,
corporate-action, raw-execution, and trading effects are all `none`. This
result cannot establish genuine raw prices, validated adjustment or action
semantics, wider schema stability, identity/lifecycle authority, publication or
correction history, `HistoricalBarSource`, admission, or trading readiness.

## Tiingo security-identity and lifecycle contract qualification

ADR 0018 adds a strict offline contract boundary after the ADR 0017
retained-field proof. Qualification accepts one exact verified research
snapshot, its exact proof-constructed ADR 0017 qualification, and one canonical
identity/lifecycle artifact. It revalidates every binding rather than accepting
caller-supplied rows or digest summaries. The acquisition profile's
`identifier_authority` string is only a frozen label and cannot serve as the
artifact or as evidence that a real mapping is correct.

The trade-enabled artifact scope is exactly DIA, IWM, QQQ, and SPY. A separate
repository-owned synthetic corpus contains a ticker-change case and a delisted,
non-tradable security. Those facts exercise stable internal identity,
effective-dated aliases, causal knowledge, and tradability while remaining
structurally unable to expand the four-symbol allow-list. Exactly four
trade-security IDs and two pairwise-isolated lifecycle IDs are permitted; no
cross-symbol or cross-venue alias can bridge the corpora. Every trade identifier
and included-universe fact must continuously cover the exact pinned session
from open through the downstream daily-bar close-time resolution instant. A
lifecycle effective instant or venue string is not calendar authority. Dates
outside the exact pinned-calendar scope require separate reviewed calendar
evidence before any production lifecycle claim.

Start from the fail-closed
[identity/lifecycle artifact template](tiingo-eod-identity-lifecycle.template.json),
copy it to an owner-only gitignored path, and replace every placeholder only
from selected exact reference evidence. The template is deliberately invalid:
zero evidence digests and empty fact arrays cannot pass qualification.

Run the credential-free operator boundary with:

```bash
make tiingo-eod-identity-qualify \
  CAPTURE=final-capture-name \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json \
  IDENTITY_LIFECYCLE=path/to/identity-lifecycle.json
```

The command verifies the exact capture and ADR 0017 proof, reads owner-only
canonical artifact bytes, and prints only secret-safe contract metadata,
checks, and counts. It will not read
`.env`, make a new provider request, write to the capture or catalog, or perform
an admission or trading transition. Qualification failures emit one generic,
value-free message rather than malformed private artifact content.

No production identity/lifecycle artifact has passed, and the existing actual
baseline has not completed identity/lifecycle qualification. Contract results
retain production-identity, raw-execution, canonical-bar, corporate-action,
historical-source, admission, and trading effects of `none`. Real identity and
lifecycle authority, genuine-raw semantics, market provenance,
corporate-action authority, production source integration, licensed admission,
independent approval, and every paper or live trading gate remain open.

## Tiingo receipt-time local lineage

ADR 0016 implements a proof-constructed, in-memory comparison of two or more
complete verified captures. Supply final basenames in strict chronological order:

```bash
make tiingo-eod-lineage \
  CAPTURES="older-final-capture newer-final-capture" \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The operator boundary verifies every named immutable tree before deriving local
versions. It requires one exact profile, policy, scope, and calendar artifact;
the command form also requires the same exact authorization artifact for every
named capture. V1 does not support profile, authorization, or calendar artifact
rotation. It records `initial`, `unchanged`, and `changed` occurrences. Changed
row economics create the next linked local receipt-time version; presentation-
only response changes do not. A missing or extra key rejects the derivation and
never becomes carry-forward data, a deletion, or a tombstone.

The command runs offline/frozen without `.env`, network, bytecode writes,
catalog changes, admission, or trading effects. Output contains only secret-safe
capture, scope, and timing metadata, policy and schema identifiers, proof
digests, counts, a research-only note, and explicit effects of `none`; it never
contains row values or response bytes. The current actual capture is a baseline,
not repeated-capture evidence. A second actual capture requires a fresh external
operator decision and must use the same exact still-applicable profile,
authorization, and calendar artifacts for v1 lineage.

## Required workflow

1. Select the exact historical product and confirm that its contract permits the
   intended local storage, normalization, backtesting, and derived artifacts.
2. Freeze the source ID, adapter version, exact ETF allow-list, coverage interval,
   identifier authority, exchange calendar, universe, and corporate-action set.
3. Qualify the provider contract and capture mechanics offline with synthetic
   fixtures before any exact response is requested or retained. This proves
   software behavior only.
4. After provider-specific profile, rights, and exact pinned-calendar approval,
   perform the bounded capture and validate the legally obtained exact bytes
   offline, then derive the value-free exact-retained field-contract proof. A
   second actual capture requires a fresh external operator decision and the
   same exact still-applicable profile, authorization, and calendar artifacts
   because v1 does not support artifact rotation. When at least two such
   complete verified captures exist, derive local receipt-time lineage. Only
   after independent genuine-raw, provenance, identity, lifecycle,
   corporate-action, source, and admission gates may a
   `HistoricalBarSource` be implemented. Keep API credentials in the
   configured secret provider; never put them in an admission document, browser
   response, log, or catalog row.
5. Run the adapter contract suite against the licensed payloads and record one
   SHA-256 digest per required check. Failed checks remain evidence; do not erase
   or relabel them.
6. Evaluate the frozen specification and evidence. The command exits nonzero for
   `blocked`, `review_pending`, or `rejected` unless explicitly run in inspection
   mode:

   ```bash
   uv run python scripts/evaluate_market_data_admission.py \
     --specification vendor-specification.json \
     --evidence vendor-evidence.json
   ```

7. A reviewer other than the evidence executor must approve the exact bundle.
   Re-evaluate it, then ingest through the vendor adapter so the same profile,
   report, checks, and manifest are published atomically.

Use `--allow-not-admitted` only to inspect a non-admitted report in CI or local
development. It does not change the report status and must never be used as a
trading-readiness signal. The standalone evaluator prints a report; it does not
mutate the catalog or grant trading authority.

## Input rules

- Start from [the specification template](vendor-specification.template.json)
  and [the evidence template](vendor-evidence.template.json). For SFP exact-page
  retention, separately start from the
  [capture-authorization template](sharadar-sfp-capture-authorization.template.json).
  For Tiingo EOD, use its
  [acquisition-profile template](tiingo-eod-acquisition-profile.template.json),
  matching
  [capture-authorization template](tiingo-eod-capture-authorization.template.json),
  and exact
  [pinned-calendar template](tiingo-eod-pinned-calendar.template.json).
- JSON keys are strict and duplicate keys are rejected.
- All timestamps must be UTC and causally ordered.
- Digests are lowercase SHA-256 values. Store only the digest of entitlement
  terms, not the contract text.
- The source ID in the evidence must match the frozen specification and the
  adapter profile.
- Missing, duplicate, or unknown technical checks invalidate the bundle.
- An approved report is still not deployment authority; paper and live modes
  retain their independent promotion, risk, broker, and reconciliation gates.

## Recommended technical checks

At minimum, preserve evidence for deterministic re-ingestion, causal revisions,
source identity, effective-dated identifiers and delistings, DST and half-day
calendar behavior, corporate actions, raw-versus-adjusted separation, schema and
quality quarantine, manifest reproduction, and full required-symbol coverage.
The exact required list is frozen in the specification and may be stricter for a
particular vendor product.
