# Wave 2 — canonical economic engine

Status: local exit gates passed; GitHub PR/CI/merge verification remains open. The branch is `codex/personal-v1-w2-integration`, based on verified [PR #52](https://github.com/km8trix/AutoQuantTrader/pull/52) at `ec63ca793ed4fe8a68397dc752000e102741da59`. W3 starts after this wave merges.

The [frozen W2 interfaces](../../contracts/personal-v1/wave2-interfaces.md) now have one causal engine, retained-reducer accounting and pure reporting. The [research runbook](../../runbooks/personal-v1-research.md) explains explicit inputs, the general worker default, model limits and private bounded publication.

## Exit evidence

| Gate | Accepted local evidence |
|---|---|
| Causal state, risk and timing | Engine tests cover fill feedback, pending targets, batch rollback, cutoff equality, half-days/DST, missing events, replay/permutation/duplicates and future-prefix stability through settlement |
| Two references × two datasets | [Four 520-session runs](long-run-verification.json), each with 252 warmup and 268 scored daily returns, independently recomputed with Fraction arithmetic and separate Decimal80 annual statistics |
| Financial/report semantics | E1–E8, exact contribution/withdrawal 21% TWR, missing marks, actions, settlement, fees, partial/UNKNOWN/cancel, corrections/busts and FIFO tests; [integration8](integration-08.json) |
| Golden compatibility | Ten canonical journal entries and cash/NAV 1044.04 match exactly; original facts retained, one-second instruction-first admission explicitly scoped |
| CLI process boundaries | Nine [source](process-source.json) and nine [installed-wheel](process-installed.json) cases: completion, privacy/nooverwrite, duplicate lock, SIGTERM, supervisor SIGKILL and orphan cleanup, restarts, wall/event limits |
| Quality and regressions | [1633 tests passed](local-checks.json),7PostgreSQL tests skipped locally; Ruff, mypy 307 files, API contracts, architecture and Compose model pass |
| Conventional package | [Two byte-identical wheels](wheel-verification.json), native hook disabled, general worker and retained HALTED simulation work outside checkout |

## Long-run results

These are labelled synthetic engineering fixtures; the figures do not establish investment performance.

| Fixture | Reference | Ending NAV | Executions |
|---|---|---:|---:|
| flat | buy_hold | 9998.56 | 1 |
| flat | trend_sma | 1E+4 | 0 |
| regime | buy_hold | 9521.7206 | 1 |
| regime | trend_sma | 9897.148 | 3 |

## Scope and remaining closeout

Reports retain data class, actual-source/build/calendar/configuration/model pins, causal accounting facts and coverage/reasons for every undefined metric. Corporate-action scope exclusions remain explicit. The five-session Tiingo sample cannot qualify default trend or annual statistics. Synthetic calendars are not real holiday/settlement-bank coverage; deterministic models are the accepted W2 scope. Golden economic parity does not qualify legacy intraday timing.

Resident memory uses nominal100 ms sampling plus measurement latency and a final high-water check; Linux additionally applies an address-space limit. This permits brief overshoot and is not an allocator reservation. The child retains the instance lock after parent death. No provider call, credential read, order, deployment, subscription or capital allocation occurred.

The former database golden loop is now the explicit `autoquant-golden-oracle` entry and historical Compose profile. Durable research jobs, real dataset selection, comparison UI and untouched holdout/trial management remain W3. Required PostgreSQL/browser/installed-wheel CI must pass before merge. After review, commit/push, create the PR, satisfy checks, merge, verify the exact merged tree and continue W3 in this orchestration task.

Earlier integration receipts1–7 and [preservation inventory](initial-preservation.json) retain their original narrower scope.
