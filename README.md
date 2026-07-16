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

The checked-in application implements the Phase 0 walking thread and a **local
Phase 1B point-in-time data-plane and fail-closed admission framework**. It remains simulation
only: it does not connect to a licensed market-data vendor or broker, submit
paper orders, or submit live orders. Paper and live startup fail closed. The
trader entrypoint remains an explicit `not_ready` diagnostic.

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
