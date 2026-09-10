# Personal historical research

The W2 general path composes one causal application engine, retained financial reducers and derived reporting. It runs offline from an explicitly selected archive or labelled engineering fixture. The process starts no broker transport or database and inherits no operational credentials. The strategy references are engineering examples, not qualified investment strategies.

`autoquant-worker` now selects this general path and accepts the same arguments as `autoquant-research`. The former fixed database fixture loop is available only through `autoquant-golden-oracle`; the historical Compose worker also requires the explicit `legacy-golden-oracle` profile. Durable general jobs and their UI are W3 work. Changing these entry points does not start a service.

## Run and inspect

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

The [W2 evidence index](../reviews/2026-09-09-wave2/README.md) records the accepted source hashes, checks and remaining gates. Golden arithmetic remains a small compatibility oracle; general research reports must come from accepted engine outputs. Durable research jobs, comparison UI and holdout/trial management belong to W3.
