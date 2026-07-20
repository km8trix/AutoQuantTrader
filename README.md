# AutoQuantTrader

AutoQuantTrader is a quantitative research, backtesting, paper-trading, and
eventually live-trading application with a desktop-oriented browser interface.
Implementation is proceeding in safety-complete vertical slices.

Start here:

- [Architecture and product scope](docs/ARCHITECTURE.md)
- [Implementation roadmap](docs/IMPLEMENTATION_PLAN.md)
- [Operational budgets](docs/OPERATIONAL_BUDGETS.md)
- [Architecture decisions](docs/adr/README.md)
- [Operational runbooks](docs/runbooks/README.md)

The first release targets a single operator, one trade-enabled strategy per
brokerage account, and a small universe of liquid U.S. ETFs using bar-based,
regular-hours, long-only trading. The React browser application is optimized for
desktop viewports; native desktop, PWA, and mobile applications are out of scope.
Live trading is gated behind point-in-time data validation, backtesting, shadow
replay, paper trading, reconciliation, and operational-readiness checks.

## Current implementation status

The local application implements the Phase 0 walking thread and a **local Phase
1A/1B point-in-time data plane and fail-closed admission framework**. Its
production worker/trading runtime does not ingest from an admitted market-data
vendor or connect to a broker, submit paper orders, or submit live orders.
Secret-safe access probes and separately authorized research-capture tools do
not change that state. Paper and live startup fail closed. The trader entrypoint
remains an explicit `not_ready` diagnostic.

The walking thread uses trusted clocks, payload-bound risk decisions, atomic
account cash reservations, single-use consumption, and a durable submission
attempt before the simulated order is recorded. Durable readiness requires the
exact Alembic schema revision plus read-only authorization, reservation,
submission, order, and ledger integrity checks; application startup never
creates production tables implicitly.

The worker now ingests a strict recorded JSONL adapter through a provider-neutral
historical-source port into immutable,
content-addressed raw and normalized Parquet objects. PostgreSQL atomically
publishes ingestion jobs, security lifecycle, calendar, universe, corporate
actions, feed entitlement, quality findings, quarantine, ordered partitions,
and manifests. Causal reads require an explicit manifest and `as_of` time. The
browser's **Datasets** and **Data quality** workspaces expose this evidence,
including the persisted admission profile, deterministic gate report, and
individual checks. The fixture is permanently blocked from admission. Selecting and admitting a real
licensed point-in-time vendor remains required before Phase 1 can be declared
complete or paper trading can begin.

The market-data boundary also supports session-defined daily bars and a bounded,
immutable Sharadar SFP research capture. SFP's adjusted OHLCV is preserved with
its actual basis and is deliberately blocked from the canonical raw execution
lane; it never enters canonical raw bars. Future exact-page capture is
fail-closed until a reviewed authorization artifact permits local research
storage for the requested dates and binds the digest of the applicable terms.
The capture does not alter admission or trading readiness.

ADR 0012's offline Tiingo EOD qualification slice is implemented against
repository-owned synthetic fixtures. It hardens strict schema parsing,
documented-raw-candidate versus adjusted field separation, corporate-action
candidates, symbol/session coverage, receipt-time causal knowledge, and
deterministic identity. Results are permanently marked `synthetic_contract_only`
and cannot emit canonical bars or admission evidence. The slice performs no
Tiingo capture and makes no claim about a live payload. Exact capture and a
production `HistoricalBarSource` remain blocked until Tiingo-specific storage
rights, the exact product and venue provenance, identity/calendar/action
authorities, publication/revision lineage, and observed bytes are reviewed and
qualified.

ADRs 0013-0015 implement the authorization-gated capture, pinned-calendar, and
descriptor-safe offline verification seams. On 2026-07-17, one bounded operation
passed its exact reviewed profile, local-retention/research authorization, and
calendar gates and retained the completed 2026-01-02 session for DIA, IWM, QQQ,
and SPY beneath the ignored owner-only capture tree. The offline verifier checked
the immutable tree, manifest and object digests, schema, calendar, and exact
four-row coverage. No response bytes are checked into Git, and this research
baseline has admission and trading effects of `none`. Every later request still
requires a fresh applicable authorization decision.

ADRs 0016-0019 add receipt-time local-lineage mechanics, exact retained-field
routing, security-identity/lifecycle contract mechanics, and market-semantics
and action-candidate contract mechanics. Lineage remains synthetic-only because
a second actual capture has not been authorized. The retained-field boundary has
qualified the exact baseline only as value-free documented candidates. No
production identity/lifecycle or market-semantics/action artifact has passed, so
the actual baseline remains neither identity-qualified nor
market-semantics/action-qualified. None of these boundaries invents vendor
publication time, historical vintages, corrections, raw-price authority,
corporate-action events, `HistoricalBarSource`, admission, or trading readiness.

ADR 0020 begins the first Phase 2 engine slice against repository-owned
synthetic events. It adds a UTC monotonic simulated clock, deterministic
availability-time ordering, non-regressing event-time watermarks in closed
order, proof-constructed complete/missing market batches, global
source/observation revision-chain binding, compact canonical decimals, typed
Phase 2 identifiers, exact versioned portfolio/risk arithmetic, and semantic
replay digests. Strategy contexts bind an
exact batch identity and digest, target tuples are immutable/sorted/unique, and
`ReplayResult.complete_batch_ids` names every strategy-eligible proof. The
walking thread now invokes its strategy through this canonical batch seam.

ADR 0021 connects repository-owned fixture manifests to that reducer through a
content-verified, all-revision RawBar tape. Calendar/universe pins produce the
inclusive decision schedule with an explicit lag, so quarantined or missing
rows remain visible as skipped evidence. A successful fixture replay can be
atomically sealed as a content-addressed run manifest with separate full-source
and projected-replay digests plus explicit runtime pins. Failed or late-event
runs write nothing. This is not a backtester, mutable job, API command, browser
result, benchmark, or trading capability. The Backtests route remains reserved
and paper/live readiness is unchanged.

ADR 0022 completes the synthetic Phase 2A strategy callback/state boundary. A
separate pure reducer canonically interleaves complete market batches with
explicit UTC clock schedules, gives every callback a typed market/clock cause
and immutable fixed-clock/context snapshot, and carries bounded versioned state
through exact predecessor-linked transitions. One captured runtime pin prevents
strategy identity, version, configuration, or state-schema drift during a run.
Its in-memory transcript hashes
the initial positions, schedule, every input/output state, and every complete
target payload. The existing sealed replay manifest remains callback-free and
unchanged.

ADR 0023 begins Phase 2B with immutable causal portfolio/price snapshots and
canonical multi-instrument intent batches. Both market- and clock-triggered
targets can now be converted without inventing price causality; full snapshots
liquidate omitted holdings, partial snapshots touch only named instruments, and
every intent carries the complete target, decision-trigger, source-price, and
strategy-configuration evidence into the risk payload hash. The Phase 0
one-position adapter remains compatible. No durable intent batch, expanded
ledger, API/browser capability, or paper/live authority has been added.

ADR 0024 adds the first canonical order/execution lifecycle reducer. Immutable
submission evidence feeds normalized per-order broker sequences for acceptance,
rejection, cancellation, partial or late fills, and exact predecessor-linked
execution corrections. Current execution heads deterministically project
cumulative quantity, remaining quantity, fees, and status while the complete
superseded transcript remains hashed. Cancel requests bind the exact observed
non-terminal order state. This still creates no broker effect, durable order,
ledger posting, or trading authority; the remaining Phase 2B boundaries are
next.

For a separately authorized future capture, start from the fail-closed
[acquisition-profile](docs/admission/tiingo-eod-acquisition-profile.template.json),
[capture-authorization](docs/admission/tiingo-eod-capture-authorization.template.json),
and [pinned-calendar](docs/admission/tiingo-eod-pinned-calendar.template.json)
templates. Copy all three to a gitignored, owner-only location, replace every
placeholder, and enable approval or permission fields only after the applicable
review. Explicitly run `chmod 600` on each copied file. Every venue, timezone,
session label, open, close, and kind in the calendar template is illustrative
and must also be reviewed and replaced where applicable, even when it is not
prefixed with `replace-`. Derive the normalized profile contract digest without
reading a credential or making a request:

```bash
make tiingo-eod-profile-inspect PROFILE=path/to/reviewed-profile.json
```

Put the printed `profile_contract_sha256` in an authorization reviewed no
earlier than the profile and in a calendar artifact reviewed no earlier than
the profile. Enable the authorization's two permission flags only when the
terms review supports them. Only then may an operator run:

```bash
make tiingo-eod-capture START_DATE=2026-07-14 \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The target defaults to all four Phase 1 symbols. Set, for example,
`SYMBOLS="DIA SPY"` only when the reviewed profile and calendar have that exact
sorted subset.

The command validates all three artifacts and the exact requested scope before
it reads `TIINGO_TOKEN`. The checked-in templates intentionally cannot authorize
a capture; the earlier bounded operation does not authorize another run.
It rejects group- or other-accessible existing capture-root components beneath
the repository; higher repository and OS ancestors are traversed without
following symlinks but need not be owner-only. Validated responses are written
to owner-only staging and become visible under their final name only through
the atomic commit rename; pre-commit faults never publish a final capture. A
process crash may leave a hidden inert staging or reservation entry, but never
a partially published final capture.

Its timeout is a finite per-request socket-I/O timeout, not a strict deadline for
the entire multi-symbol capture; use an external supervisor when a hard
whole-process deadline is required.

After a capture exists, verify it without loading credentials or making a
request:

```bash
make tiingo-eod-verify \
  CAPTURE=final-capture-basename \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The verifier uses the fixed ignored capture root, writes no state, and emits no
payloads or prices.

## Quickstart

Prerequisites are Docker with the Compose plugin and available local ports 5173,
8000, and 5432. From the repository root:

```bash
cp .env.example .env
make dev
```

The single command builds and starts PostgreSQL, applies migrations, starts the
API and desktop-oriented browser application, ingests the deterministic Phase
1A fixture, and runs the trader fail-closed diagnostic. Wait for the API and web
health checks, then open:

- Browser application: <http://localhost:5173>
- API documentation: <http://localhost:8000/docs>
- API liveness: <http://localhost:8000/health/live>
- API readiness: <http://localhost:8000/health/ready>

Stop the foreground stack with `Ctrl-C`, then run `make down`. The PostgreSQL
and content-addressed data-lake volumes are preserved; deleting them is
intentionally not part of the normal shutdown command.

## Host development and checks

Host-based development requires Python 3.12, `uv` 0.11.28, Node.js 22, and pnpm
11.7.0. Install locked dependencies and run the complete current quality gates:

```bash
make bootstrap
make check
```

`make check` includes backend and browser tests. Useful focused commands are
`make test`, `make api`, `make web`, `make worker`, `make trader`, `make migrate`,
and `make compose-check`. After changing an HTTP response
contract, run `make api-contracts`; `make api-contracts-check` and CI fail when
the checked-in OpenAPI document or generated browser wire types are stale. These
generated types provide compile-time checking only; the HTTP client does not yet
perform runtime response validation. The browser calls same-origin `/api/v1`
endpoints through the Vite proxy; deterministic UI fixtures are off by default
and require an explicit `VITE_USE_DEV_FIXTURES=true` opt-in.

The reusable admission evaluator accepts strict, secret-free JSON specifications
and evidence bundles. It exits nonzero unless the result is actually admitted:

```bash
uv run python scripts/evaluate_market_data_admission.py \
  --specification path/to/frozen-specification.json \
  --evidence path/to/evidence.json
```

See [Market-data admission](docs/admission/README.md) before preparing a vendor
evidence bundle.

Candidate connectivity can be checked without printing credentials, downloading
bulk history, or changing admission state:

    make market-data-probe DATE=2026-07-14 SYMBOL=SPY

The probe parses the owner-only, gitignored .env without interpolation or shell
evaluation, loads only the three market-data keys into its process, makes one
bounded read per candidate, and reports sanitized access facts. A successful
probe is not license, point-in-time, or admission evidence by itself.

A completed Sharadar range can be archived for offline, research-only
qualification only after storage rights are reviewed:

```bash
make sharadar-sfp-capture START_DATE=2026-07-14 \
  AUTHORIZATION=path/to/reviewed-authorization.json
```

Start from the fail-closed
[authorization template](docs/admission/sharadar-sfp-capture-authorization.template.json),
replace its IDs and terms digest, and set its permission flags to `true` only
when the review supports both local snapshot storage and research use. Exact
pages and their secret-free manifest always stay under the fixed, gitignored
`.local/vendor-snapshots/sharadar-sfp` tree. The manifest binds the reviewed
authorization, terms, and observed response-column schema; offline loading also
binds the exact capture to the pinned calendar semantics. Admission and trading
effects remain `none`.
