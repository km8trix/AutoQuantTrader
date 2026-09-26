# AutoQuantTrader operating instructions

## Start and resume

- Run `git status --short --branch` and `git log -5 --oneline`; preserve unrelated changes.
- Read `docs/SPEC.md`, `docs/STATUS.md`, `docs/PLAN.md`, then relevant architecture,
  testing, decisions, source and tests. The repository is durable memory.
- Work in the selected feature checkout. The surrounding AutoQuantTrader directory
  contains old worktrees and private artifacts; do not infer the active revision
  from its name. Do not bulk-read `.env`, credentials or runtime directories.
- `docs/PLAN.md` breaks the existing `docs/IMPLEMENTATION_PLAN.md` wave roadmap
  into resumable tasks. Frozen `docs/contracts/personal-v1/` requirements and the
  dated account amendment remain authoritative; historical ADRs describe their
  own scope. See `docs/DECISIONS.md` for precedence.

## Execute autonomously

Read spec/status/plan → select highest-priority unblocked task → implement → test
→ inspect results → fix failures → retest → update docs/status → commit a focused
change when appropriate → continue to the next unblocked task.

Preserve existing working behavior unless the specification requires a change.
Prefer root-cause fixes and small, independently verifiable changes. Do not
rewrite working systems, relax tests, extend safety limits, or turn a skip into
acceptance. A task is complete only when its acceptance criteria and applicable
validation pass. Record commands, outcomes, skips and remaining limitations.

Continue without asking permission for routine reversible engineering. Ask only
for unresolved consequential product/architecture choices, conflicting
requirements, missing necessary credentials/access, irreversible actions, live
capital effects, or a blocker after reasonable investigation. Continue independent
work while a dependency is blocked. Do not infer approval from elapsed time.

Keep `docs/STATUS.md` concise and update it after each meaningful task, failed
validation or handoff. Put detailed evidence under `docs/reviews/`; record
significant decisions in `docs/DECISIONS.md`. Correct inaccurate spec/plan/architecture
as verified facts emerge. Never overwrite earlier failed evidence with a pass.

## Safety and architecture

- Live trading, real orders/positions/funds, authentication weakening, risk
  increases and simulation-to-live transitions require explicit owner approval.
  Never use production credentials for testing. Development defaults to offline fixtures.
- Never print or commit secrets, provider payloads or private session paths.
  Provider reads, OAuth and deployment remain separately scoped operations.
- Strategies emit targets; portfolio/risk authorize intents. Preserve exact
  accounting, causal availability and later-event fills, durable attempts before
  I/O, UNKNOWN on ambiguity, account leases/fencing and authoritative reconciliation.
- Startup remains HALTED and trading authority false. Healthy services, successful
  builds, fixture results and data hashes do not confer execution permission.
- Preserve one canonical causal engine. Domain/pure code cannot import effect
  authority; packages cannot import application composition roots.
- Treat execution, sizing, leverage, stops, limits, kill switches, adapters and
  credentials as safety-critical: require adverse/restart/concurrency tests and
  documented limits before acceptance. Backtests imply no future profitability.
- Do not casually change frozen contracts, ledger/schema migrations, lease or
  timeout bounds, native/signing/seal machinery, CI gates, historical evidence,
  generated API contracts or lockfiles. Inspect owners/callers and migration
  requirements first. Never remove old worktrees or activate native services as cleanup.
- At most three additional workers globally; no nested workers. Assign exclusive
  files and coordinate shared schema/accounting changes.

## Validation (from this checkout)

See `docs/TESTING.md` for clean-environment commands and prerequisites. Run the
architecture check before project imports. Reuse a verified Python 3.12 runtime;
never source `.env` or start the application stack to validate a code change.

| Check | Command with prepared dependencies |
|---|---|
| Architecture | `.venv/bin/python -I -B scripts/check_personal_architecture.py` |
| Formatting | `.venv/bin/ruff format --check .` (apply: `.venv/bin/ruff format <changed-paths>`) |
| Lint | `.venv/bin/ruff check .` |
| Types | `.venv/bin/mypy apps packages` |
| Standard tests | `.venv/bin/python -B scripts/run_personal_tests.py` |
| PostgreSQL tests | Same runner with `--postgres-url "$AQT_DISPOSABLE_TEST_DB"` (disposable DB only) |
| API contracts | `.venv/bin/python -B -m scripts.generate_api_contracts --check` |
| Browser | `make frontend-check` (lint, typecheck, tests, bundle tests, build) |
| Wheel | `uv build --wheel --no-sources --build-constraints build_support/native_build_constraints.txt --require-hashes --out-dir "$AQT_BUILD_OUTPUT"` |
| Compose model | `make compose-check` (configuration only) |
| Documentation | `git diff --check` plus local link/command review |

`make check` is the broader wrapper, but may synchronize dependencies. Raw `pytest`
selects historical/native suites too; use the standard runner or scoped tests with
sanitized environment. A PostgreSQL skip is not concurrency acceptance. Use focused
checks for small changes; require affected financial/integration gates for behavior
changes and exact-revision Linux CI for release. Fix new failures before dependent work.

Existing end-of-wave closeout remains: after all exit gates pass, commit/push,
open a PR, satisfy CI/review, merge through GitHub and verify the merged revision
before the next wave. No force push or bypassing protection; incomplete Wave 4
cannot be closed by documentation or component passes.
