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

ADR 0013 adds the next acquisition seam, but its behavior has been exercised
only with repository-owned synthetic responses and an injected test transport.
It has not made a live Tiingo request or retained a Tiingo response. Actual
operation remains fail-closed until a Tiingo-specific acquisition profile
records human approval of the exact product and scope and a separate, matching
authorization confirms the applicable terms, local-retention rights, and
research-use rights, and an exact canonical pinned-calendar artifact records
approval against that profile. Reviewer identifiers are auditable attestations;
reviewer authentication and separation of duties remain external governance
controls. Credentials and a successful access probe cannot satisfy that gate.
If those external prerequisites are later met, acquisition remains staged
through allow-listed per-symbol request/receipt evidence,
response-size and socket-I/O bounds, and atomic publication of immutable,
secret-free capture metadata beneath `.local/vendor-snapshots/tiingo-eod`.
Provider admission review remains a later gate.

ADR 0014 adds a separate network-free verifier for a published final capture.
Its path, immutable-tree, authorization/profile, content digest, response
contract, per-symbol pinned-calendar, and exact session-coverage checks are
exercised only with synthetic captures. It accepts a strict final capture name
under the fixed root rather than an arbitrary path; that name commits to the
full canonical manifest SHA-256. The verifier retains and finally revalidates
the selected name, inode identities, metadata, and exact tree, requires the
exact reviewed authorization bytes, and proof-constructs a research-only
snapshot whose canonical-bar, revision-lineage, admission, and
production-source conversions fail closed. The reusable wrapper deliberately
does not implement `HistoricalBarSource`. No actual Tiingo capture has been
verified. Before ADR 0015, this boundary remained library-only because no
reviewed portable calendar-artifact contract existed; it did not substitute the
small synthetic reference calendar for operator input.

ADR 0015 adds that portable boundary without assigning a production calendar.
A strict canonical pinned-calendar artifact freezes the reviewed profile
digest, authority, attested tzdata-version label, exact scope, per-symbol
calendar identity, and explicit UTC sessions. Capture requires those exact
bytes before credential or transport access and commits their SHA-256 to the v2 manifest. Offline
verification requires the same bytes and derives calendars only from them. A
credential-free operator command exposes secret-free proof digests and counts
while retaining admission and trading effects of `none`. All behavior remains
synthetic-tested; no production artifact or actual Tiingo capture has been
approved or verified.

The acquisition seam makes no claim about Tiingo publication time, historical
vintages, or corrections. Receipt time is not relabeled as
`vendor_published_at`, and repeated-capture local revision lineage is deferred
to a later Phase 1 slice. The seam cannot emit canonical bars, implement
`HistoricalBarSource`, grant admission, or change paper/live trading readiness.

If the external profile, rights, and calendar reviews are later completed, start
from the fail-closed
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
a capture, and this command has not been run against Tiingo during development.
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
