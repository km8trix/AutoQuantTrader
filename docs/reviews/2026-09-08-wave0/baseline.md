# Wave 0 baseline and acceptance evidence

Measured on 2026-09-08 America/New_York (2026-09-09 UTC), code/main HEAD `107fa791bb52e9fa42cbce65992ea1ce9168834e`, branch `codex/personal-use-planning-20260908`, active checkout `/Users/spencer.karrat/Documents/GitHub/AutoQuantTrader`. This is a bounded offline baseline, not a release/full-suite/provider/production qualification. [The canonical plan](../../IMPLEMENTATION_PLAN.md) owns the exit assessment.

## Exact input and method

`initial-document-manifest.json` identifies all nine pre-existing modified/untracked consolidated documentation files by SHA-256. Initial architecture SHA-256 `b7aab5a560655277835789e3a63db68d06d9d1a6eef5a9040b848b5c82167d06`; plan `f04690d0272f5aceef7b6192dec589be59f640da4b566657f62d8c9dbdc30d23`; operational budgets `960eb14ba6b78e0dab65569053de273eb68cc6888397e9d36ed7dc893bf27728`. No application code changed during planning or Wave 0. The final artifact manifest identifies the added contract pack and canonical document edits separately.

Commands were inspected in `Makefile`, `pyproject.toml`, CI, pytest configuration, selected test fixtures, API contract generation, Compose and frontend configuration before execution. No blanket `make check` or project bootstrap was run: the old architecture-first aggregate would stop on inherited document constraints. Individual authorized baseline checks were recorded without altering that checker or bypassing any operational guard.

The checkout `.venv/bin/python` is a dangling link to `/tmp/autoquant-uv-python/...`. A unique evidence directory `/private/tmp/aqt-wave0-f152ahl7` instead holds an offline temporary CPython 3.12.13 environment, populated with **53 cached locked distributions**, using `uv sync --offline --locked --no-install-project --no-build --all-groups` against only copied `pyproject.toml`/`uv.lock`. The system sandbox required approved access to the existing uv cache; no network, project build, native lifecycle activation or checkout environment repair occurred. Python tool versions: pytest 8.4.2, Ruff 0.15.21, mypy 1.20.2. Exact toolchain is in `toolchain.json`.

The runner (`run_baseline.py`) constructed a small explicit environment with no inherited runtime credentials/DSNs, disabled pytest plugin autoload and bytecode/cache writes in source, and routed logs, SQLite fixtures and all generated evidence into the temporary directory. PostgreSQL URL was absent and no explicit test DSN was supplied. All selected broker tests use repository fixtures/injected offline transports; no account requests or vendor/trading commands ran. API tests used in-process clients and disposable SQLite files.

Frontend commands used a narrow sandbox of tracked `apps/web` files only so Vite's `loadEnv` could not read checkout `.env` files. Existing installed dependencies were referenced read-only; all **25 direct dependency versions match the lockfile**. Node 20.20.2 satisfies the declared engine but differs from CI Node 22; pnpm available 11.19.0 differs from declared 11.7.0, and no pnpm install was needed. Type build info, Vite artifacts/cache and bundle tests stayed in the sandbox. This verifies existing dependency installation, not a fresh full transitive pnpm restore.

## Outcomes

| Check | Result | Count / evidence |
|---|---|---|
| Core accounting and temporal units, 16 files | PASS | **236 passed**, 0 failed/skipped |
| Risk, broker protocol, OAuth and clock units, 10 files | PASS | **421 passed**, 0 failed/skipped |
| SQLite submission/risk/backtest/API integration, 4 files | PASS | **84 passed**, 0 failed/skipped; one Starlette/httpx deprecation warning |
| PostgreSQL concurrency, 1 file | SKIPPED | **7 skipped**, no disposable PostgreSQL DSN; not database contention/migration evidence |
| Ruff format | PASS | **689 files** already formatted |
| Ruff lint | PASS | No violations |
| mypy | PASS | **281 source files**, no issues |
| Generated OpenAPI/browser contracts | PASS | Existing artifacts current |
| Architecture checker | FAIL | **6 violations**, detailed below; no checker/source repair |
| Compose model | PASS | `docker compose --env-file /dev/null ... config --quiet`; no daemon/service start |
| Trusted-time Compose verifier | PASS | Evidence-only isolation admitted; 0 inbound ports; new exposure false |
| Browser ESLint | PASS | 0 warnings/errors |
| Browser types | PASS | Both app and Node TS configurations |
| Browser component suite | PASS | **16 files / 67 tests** |
| Node bundle admission unit suite | PASS | **33 tests**, 0 failed/skipped |
| Production browser build and bundle admission | PASS | 27 assets, largest 277,872 bytes, initial graph 615,022 bytes; authorization flags false |

Totals: **741 Python tests passed, 7 skipped, 0 failed; 100 browser/bundle tests passed, 0 failed/skipped**. There are 18 baseline command records: 16 PASS, one architecture FAIL, one all-skipped PostgreSQL selection. Independent economics verification is a separate contract check and is not added to these pre-existing test counts.

`commands.json` records exact argv, working directory, elapsed time, exit and log path for all 18 checks. `check-output/` and JUnit XML preserve result details. Original temporary runner logs are copied as text here because the repository ignores directories named `logs`. Command records retain both the preserved output path and original temporary log path. The quality-script process exit itself is not used as an aggregate pass: each child command exit is inspected independently.

## Independent economic contract review

The orchestrator separately recomputed seven numerical cases with Decimal and exact Fraction arithmetic, importing no application code: **113 equalities passed**, plus the no-same-trigger-fill flag. Six invalid/undefined scenarios were manually reviewed. Covered buy/sell fees and settlement, dividend accrual/payment, split/FIFO sale, intraperiod contribution and withdrawal TWR, correction/duplicate/bust, and partial-fill/cancel/late-fill target accounting. `economics-verification.json` binds the exact oracle SHA-256; `verify_economics.py` records independent equations. This proves the specification arithmetic, not an implemented general engine. E4/E5 each link two 10% subperiods to 21% TWR; period-end contribution subtraction would incorrectly report 26% in E4.

## Six architecture findings and migration impact

The complete checker ran for 190.959 seconds and reported exactly:

1. `docs/ARCHITECTURE.md`: documented checker invocation must be exact/singular.
2. `docs/IMPLEMENTATION_PLAN.md`: same exact invocation obligation.
3. `docs/ARCHITECTURE.md`: native opaque launch-lock lifecycle documentation claim must be exact/singular.
4. `docs/ARCHITECTURE.md`: its activation-blocker claim must be exact/singular.
5. `docs/IMPLEMENTATION_PLAN.md`: same native lifecycle claim.
6. `docs/IMPLEMENTATION_PLAN.md`: same native activation-blocker claim.

These are failures against the **pre-existing consolidated document state**, whose authoritative target supersedes native lifecycle prerequisites. They are not new application failures or passing architecture qualification. No other source-boundary violation was reported by this run. W1's serialized checker/build migration must replace obsolete exact-prose obligations with canonical-document/link and standard runtime behavior checks, preserving import direction, effect isolation, resource bounds, halt and ownership invariants. Reintroducing obsolete future prose or regenerating integrity pins merely to turn this baseline green would misrepresent the target.

## Deliberate limits

Full backend/native suites, native wheel/sdist/compiler/platform seals, Linux/container image qualification, service startup, database restore, PostgreSQL migrations/locking and remote CI were not executed. No claim is made that they pass. No E*TRADE/Tiingo account/capture, actual quotes, source rights, token lifecycle, deployment, backups, alerts or live execution was qualified. Public documentation used in the account contract is a contract fact source, not account evidence.

The Wave 0 exit concerns frozen contracts, migration ownership, independent arithmetic, preserved status and an honest baseline. Recorded pre-existing checker findings and unavailable external/runtime environments remain work for their mapped later gates. They do not create a fictitious successful release, and they do not prevent finishing this bounded contract wave.


## Exit assessment and closeout

Wave 0 is complete as a contract/baseline gate. Both bounded collaboration lanes completed; an additional read-only review by the same core worker found W4 lane labels and forward-capture ownership gaps, which the orchestrator corrected against the canonical plan. Cross-lane callback/reservation sequencing, risk-versus-reduce-only wording, settlement model/actual availability and read/preview-versus-order authority were aligned. No third worker or successor task was created.

Eight archive actions were confirmed after the file-backed closeout was installed: the superseded orchestrator and seven stale tasks with completed final turns/recorded HOLD outcomes. The interrupted Docker fault-case builder remains inactive/preserved. Archived does not mean unfinished native implementation passed. `archive-results.json` preserves receipts; the monitoring parent and unrelated tasks were untouched.

`final-preservation.json` confirms all 39 worktree HEADs unchanged and all 38 non-active worktree status fingerprints unchanged. Application source has no diff. Of the initial documentation, only the canonical architecture/plan/budgets and ignored `AGENTS.md` continuation notes were updated by W0; the original README/index/review/ADR changes remain preserved. `final-artifact-manifest.json` binds the contract/evidence/continuation files (excluding its own self-reference). No source implementation, commit, push, PR, merge, provider call, deployment or live activation occurred. Wave 1 requires a new authorized turn and the prerequisites in canonical plan section 15.
