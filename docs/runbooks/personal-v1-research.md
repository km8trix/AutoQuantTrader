# Personal historical research

The W2 general path composes one causal application engine, retained financial reducers and derived reporting. It runs offline from an explicitly selected archive or labelled engineering fixture. The process starts no broker transport or database and inherits no operational credentials. The strategy references are engineering examples, not qualified investment strategies.

`autoquant-worker` now selects this general path and accepts the same arguments as `autoquant-research`. The former fixed database fixture loop is available only through `autoquant-golden-oracle`; the historical Compose worker also requires the explicit `legacy-golden-oracle` profile. The durable queue uses the separate `autoquant-research-jobs` command below. Changing these entry points does not start a service.

## Durable local research workspace

The browser workflow uses an explicitly selected database plus a private immutable object directory. SQLite supports supervised single-host research; PostgreSQL is also supported. Both API and worker must use the same database, object directory and installed source build. The API owner must match the catalog registration owner. Owner identifiers start with a letter or digit and may also contain dots, colons, underscores or hyphens (maximum 128 characters). The worker processes all eligible jobs in its selected database; `--owner-id` controls registration and does not filter worker claims. No E*TRADE or Tiingo credentials are needed to run an already admitted archive.

File-backed research SQLite uses write-ahead logging (WAL), `synchronous=FULL` on each connection, and SQLite's default automatic checkpoint. It keeps the five-second busy timeout and 60-second job lease. Readiness and report snapshots can then coexist with worker commits; writers still serialize and database failures remain visible. Use a local filesystem on one host, with the database and its `-wal`/`-shm` files together. Network filesystems are unsupported. Stop other processes before the first conversion of an existing database. WAL persists across restart; never remove its sidecar files to clear a lock. See the [SQLite WAL documentation](https://sqlite.org/wal.html) for concurrency, durability and checkpoint behavior.

The research connection checks the actual SQLite runtime and refuses versions without the documented WAL reset correction. Use SQLite 3.51.3 or later; the patched 3.50.x branch from 3.50.7 and 3.44.x branch from 3.44.6 are also accepted. The verified Python 3.12.13 environment uses SQLite 3.53.1. The Python version alone does not establish its linked SQLite version. A runtime or WAL activation failure prevents research startup; it does not silently fall back to another mode. In-memory databases, PostgreSQL and non-research engine creation keep their existing configuration.

Create a new private directory outside the checkout and install the locked runtime dependencies and project into a separate environment, preserving any existing checkout environment. Substitute absolute paths in these examples. The database parent directory must already exist. `init` only accepts an empty database and applies packaged migrations through `0039_personal_research`; it never upgrades an existing operational database implicitly.

```sh
umask 077
mkdir -p /absolute/private/research
UV_PROJECT_ENVIRONMENT=/absolute/private/research/venv uv sync --locked
/absolute/private/research/venv/bin/autoquant-research-jobs \
  --database-url sqlite+pysqlite:////absolute/private/research/research.sqlite \
  --artifacts /absolute/private/research/objects init
```

For an existing operational database, stop its writers, retain a tested backup, and apply the normal reviewed Alembic migration separately. W3 adds nine tables and preserves earlier financial history. Its downgrade refuses retained research history. Do not remove tables to make downgrade succeed. The API's normal health/readiness and research availability are separate from account reconciliation or trading eligibility.

Register an already admitted portable archive and its reviewed settlement calendar. Registration verifies exact archive, calendar and input identities; it does not fetch a provider, infer rights or upgrade data quality. Keep the raw archive and the whole private directory out of Git.

```sh
/absolute/private/research/venv/bin/autoquant-research-jobs \
  --database-url sqlite+pysqlite:////absolute/private/research/research.sqlite \
  --artifacts /absolute/private/research/objects register \
  --dataset /absolute/private/imported-research.json \
  --settlement-calendar /absolute/private/settlement-calendar.json \
  --display-name 'My admitted historical sample' \
  --prior-access known_accessed \
  --access-description 'Previously inspected exploratory history; no untouched holdout claim.'
```

Use `register --fixture regime --fixture-sessions 520` instead of the two archive arguments for labelled engineering data; supply a display name and an honest prior-access description. Synthetic weekdays are never presented as an exchange calendar. Re-registering with a new declaration creates a new catalog identity; retain the returned catalog ID.

Run the API in one terminal with explicit local configuration, and the worker in another:

```sh
AQT_ENVIRONMENT=local \
AQT_DATABASE_URL=sqlite+pysqlite:////absolute/private/research/research.sqlite \
AQT_RESEARCH_ARTIFACTS_PATH=/absolute/private/research/objects \
AQT_DATA_LAKE_PATH=/absolute/private/research/data-lake \
AQT_LOCAL_OPERATOR_ID=local-operator \
AQT_API_HOST=127.0.0.1 \
/absolute/private/research/venv/bin/python -m uvicorn apps.api.main:create_app --factory --host 127.0.0.1 --port 8000
```

```sh
/absolute/private/research/venv/bin/autoquant-research-jobs \
  --database-url sqlite+pysqlite:////absolute/private/research/research.sqlite \
  --artifacts /absolute/private/research/objects \
  --owner-id local-operator work
```

Start `pnpm --dir apps/web dev --host 127.0.0.1` and open `http://localhost:5173/research/backtests`. The default API CORS origin is `http://localhost:5173`; set `AQT_CORS_ORIGINS` explicitly when changing that origin. Use only the loopback browser/API in this local profile. The UI obtains a local HttpOnly session and CSRF capability; no provider credentials enter the page. The old golden diagnostics remain under Research history.

Choose a registered dataset, reference strategy, warmup, costs and scored interval. A blank scored interval uses admitted observed sessions while leaving a following calendar session for execution. An explicit interval outside that support is rejected. The five-session real sample needs an explicitly short configuration, for example buy-and-hold, zero warmup and lookback two; it cannot support annualized statistics or default trend history. Four-symbol allocation 0.2375 is a reference configuration, still subject to independent cash/risk checks.

The worker publishes completed or incomplete reports with their exact input, source, attempt, report and object hashes. Open a retained run to inspect NAV/wealth, SPY and cash benchmarks, metric reasons, orders/fills, FIFO matches, journal and provenance. Decimal text is authoritative; chart coordinates are a visual approximation. Missing valuations remain gaps. Select two through eight compatible reports for a comparison; different costs/configurations remain labelled and unsupported bases are rejected. Exports retain the typed report artifact and economic/source limitations, rather than only the screen's summarized metrics. Exports may contain licensed market observations; keep them private according to the source rights.

### Cancellation, restart and publication

`work --once` processes at most one claim; `--max-jobs N` bounds one invocation to at most 256 jobs. One per-user advisory process lock serializes research execution on this host. A worker claims a database lease for 60 seconds, heartbeats every ten seconds, and checks durable control throughout input loading, engine execution, report validation and publication. An owner cancel is terminal; its pending status remains visible until acknowledged. SIGTERM/SIGINT stops the worker and abandons active work for recovery. A graceful abandonment immediately releases its claim for recovery; an unacknowledged dead claim must first expire. Recovery permits at most three total attempts; failed or owner-cancelled jobs are not automatically retried. Restart with the same command and retained database/store. Do not edit leases, attempt records or activity timestamps.

A final database fence and cancellation check authorizes each publication. A stale process cannot publish over the current claim. The child uses W2's sole engine, accounting and report path. It resolves retained inputs and validates the full report inside the bounded process; the parent receives a small manifest and transfers verified bytes in bounded chunks. Jobs allow at most 32 MiB inputs, 64 MiB report output, one CPU, 4 GiB resident-memory budget and 30 minutes. Limits remain conservative process controls: sampled resident memory can briefly overshoot, reviewed metadata encoding is bounded but not independently preempted, shutdown can add five seconds, and local filesystem/database calls must return. This is not a hostile-code or kernel-I/O sandbox.

The private store uses owner-only directories/files, immutable content addressing, no-clobber installation and fsync. Content hashes detect changed bytes but are not independent evidence against an administrator rewriting the whole database and store. Preserve a consistent database and complete object directory together for backup. Stop the API and worker before backing up this local workspace; use [SQLite's online backup API](https://sqlite.org/backup.html) to produce the database snapshot, then copy the complete immutable object directory while writers remain stopped. A raw copy of the main database alone can omit committed WAL contents. Validate the restored schema and report/object bindings in a separate directory before relying on the backup. Failed attempts can leave unreferenced objects; there is no automatic garbage collection. Removing private artifacts can make retained reports or catalog entries unavailable.

### Descriptive experiments

Experiments freeze the hypothesis, source/class/calendar/build pins, prior-access declaration, candidate configurations and chronological train/validation/test windows before creating every trial job atomically. Each candidate/window runs all four cost scenarios: base, 2×, 3× and adverse. The registry is bounded to 256 trials. Each window declares its preceding warmup and uses fresh account/strategy state; scored validation/test windows do not overlap across folds. The two reference rules have an explicit identity/no-fit artifact with no learned parameters. They do not pretend that unused preprocessing was trained. Unsupported fitted strategies, carry policies and nonzero purge/embargo are not silently accepted.

Known-accessed history cannot be downgraded to unknown. Neither class is described as an untouched holdout. These experiments are descriptive engineering/economic comparisons, and suitability remains `not_assessed`; no winner or live eligibility is generated. Independent training-scope and future-perturbation checks support software isolation. Owner-declared strategy criteria and a frozen-candidate forward qualification remain later gates.

## Standalone run and inspect

After installing the conventional wheel using the [foundation runbook](personal-v1-foundations.md), run:

```sh
autoquant-research --fixture flat --strategy buy_hold --output flat-buy-hold.json
autoquant-research --fixture regime --strategy trend_sma --output regime-trend.json
```

The fixtures contain 520 weekday sessions, of which 252 are warmup and 268 are scored. Their calendar is explicitly synthetic and does not claim real holiday or settlement-bank coverage. The separate extra calendar session defines the last decision's potential execution window; it does not extend the scored interval or invent a fill. The flat fixture has price 100; the regime fixture follows its declared rising/falling formula. Neither is historical market evidence.

Reference options include `--lookback`, `--allocation`, `--rebalance-sessions`, `--initial-cash`, `--slippage-bps` and `--fee-per-share`. The default single-instrument allocation is 25%; a four-instrument imported universe defaults to 23.75% each before whole-share rounding and the cash buffer. Risk independently checks every proposed batch and its execution-time price/capacity. A configured target is not an approval.

The report JSON retains the run specification, data class and limitations, valuations, flows, effective executions, FIFO matches, journal, trace and metric coverage. Monetary values are exact decimal strings. An artifact attempt ID and generation time identify publication; the run ID binds data, configuration, calendars, source content, dependency lock and economic/report conventions. The build base revision is explicit, and complete actual source content includes any working edits without claiming a clean Git checkout.

A report may contain undefined metrics. Annualized statistics need a funded baseline and at least 252 complete scored daily returns. Missing/stale NAV, a missing exact flow-boundary mark, zero variance or no completed trade group retain specific reasons. A terminal open position remains in marked NAV; there is no forced liquidation. Contributions and withdrawals create capital changes, with event-timed return subperiods and the same analytical benchmark flow clock.

## Imported archive

Use a previously admitted W1 portable research archive and a separately reviewed settlement-business-date JSON:

```sh
autoquant-research --dataset imported-research.json \
  --settlement-calendar settlement-calendar.json \
  --strategy trend_sma --warmup 252 --lookback 200 \
  --output imported-trend.json
```

The settlement file has exactly `calendar_id`, `version`, `timezone` (America/New_York) and an ordered unique `business_dates` array of ISO dates. It must cover the dated T+3/T+2/T+1 cycles and any explicit correction receipt dates. Exchange and settlement calendars are different inputs; the runner does not infer real trading days from weekdays or settlement dates.

The archive's final session is reserved solely as the next-session calendar horizon. The report explicitly lists the earlier scored sessions and this limitation. Supply enough preceding sessions for warmup and scoring. The existing five-session Tiingo sample can demonstrate plumbing with an explicitly short configuration, but cannot qualify default trend or annualized performance. Previously inspected sample dates are not untouched holdout.

Raw opening prices feed an explicitly labelled retrospective next-open proxy. Completed daily rows retain modeled 20:00 ET historical availability and any actual later receipt as separate provenance. Adjusted closing prices feed features and the total-return benchmark; they are never execution prices. Daily prices do not establish quote spread, queue position or liquidity. Dividend/split candidates without explicit supported entitlement, action and payable facts reject the affected imported scope.

## Resource and publication behavior

The parent holds one per-user research instance lock and starts a single Python child with an explicit clean environment. Defaults are 30 minutes, one Python CPU, a 4 GiB resident-memory budget, 100,000 events and 1 GiB report output; CLI options may lower those limits. POSIX CPU/file limits and a parent wall watchdog bound the process. The parent samples only its child's resident size about every 100 ms and kills it on excess or measurement failure; a final high-water check rejects publication after a transient excess. Linux additionally enforces an address-space limit. Sampling permits brief overshoot and is not an allocator reservation or a hostile-code sandbox. The resource model is pinned and labelled in every run. Cancellation, deadline termination and resource exhaustion never publish a completed artifact.

This Mac rejected a 4 GiB `RLIMIT_AS` setting; resident size is a different quantity from virtual address space. The implementation uses the documented [Python resource measurements](https://docs.python.org/3/library/resource.html) and explicit process sampling instead of treating an unavailable limit as enforced. The CLI fails visibly when those measurements are unavailable.

The child retains the same advisory-lock descriptor until exit and checks supervisor liveness at engine and publication boundaries. An abruptly killed parent cannot release the lock while its child still runs. Resident sampling has a nominal 100 ms interval plus measurement time (a failed one-second measurement ends the run).

The output parent directory must exist. Report publication is atomic and refuses an existing path. Files are owner-readable/writable only. Raw input payloads, provider credentials and private input paths are not printed in error messages. Run identity or JSON export cannot enable trading.

## Completion evidence

The [W2 evidence index](../reviews/2026-09-09-wave2/README.md) records the accepted economic engine. The [W3 evidence index](../reviews/2026-09-09-wave3/README.md) records durable workflow and browser checks and their current acceptance status. Golden arithmetic remains a small compatibility oracle; general research reports come from actual engine outputs.
