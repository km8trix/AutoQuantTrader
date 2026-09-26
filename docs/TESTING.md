# Testing and validation

This is the current personal-profile validation guide. Historical/native and
credential-aware deployment runbooks remain scoped evidence, not prerequisites
for ordinary offline development. Record the tested commit, commands, outcomes,
skips and limitations in `STATUS.md`; preserve a failure until its actual repair
passes the relevant gate. A green synthetic test cannot authorize trading or
qualify a provider, account, clock, calendar or genuine captured session.

## Environment and safety

- Run from the repository root after reviewing `AGENTS.md` and current status.
- Python supports 3.12–3.13; standard CI pins Python 3.12.13 and uv 0.11.28.
  Browser CI uses Node 22 and pnpm 11.7.0. Dependencies are locked in `uv.lock`
  and `apps/web/pnpm-lock.yaml`. Do not replace an existing qualified environment
  or activate the historical custom native build hook incidentally.
- Use only fixture data and temporary storage for ordinary checks. Never read
  `.env`, private provider captures or production credentials to make tests run.
- PostgreSQL checks perform migrations and cleanup. Select an explicitly
  disposable database, never an operational database. A passing SQLite test is
  not PostgreSQL concurrency evidence.
- The personal runner discards ambient environment, disables automatic pytest
  plugin loading, gives tests a private temporary directory and UTC timezone,
  and forwards only the explicitly supplied PostgreSQL test URL. Raw pytest
  does not provide all those safeguards. The autouse fixture removes ambient
  `AQT_DATABASE_URL`, but that alone is not complete isolation.
- `uv run` can synchronize/install dependencies. Prefer verified tools directly
  when preserving a qualified environment. If a new environment is needed,
  install locked dependencies without project/native build execution:

  ```sh
  UV_PROJECT_ENVIRONMENT=/private/tmp/aqt-dev-venv \
    uv sync --offline --locked --all-groups --no-install-project --no-build
  ```

  Use a new destination if this example directory already contains unrelated
  work. Offline cache misses are setup blockers, not reasons to loosen locks.
  The commands below assume `AQT_PYTHON` points to that verified interpreter;
  substitute an existing verified environment when available:

  ```sh
  AQT_PYTHON=/private/tmp/aqt-dev-venv/bin/python
  ```

## Required checks by change

| Change | Minimum applicable evidence |
| --- | --- |
| Documentation only | Review links/commands against code; `git diff --check`; inspect diff for secrets and unintended changes |
| Python behavior | Architecture, format, lint, types, directly affected unit/integration cases |
| Financial or execution boundary | Above plus independent accounting/risk/reconciliation/failure oracles and relevant persistence/concurrency cases; never increase acceptance limits to pass |
| Schema/persistence | Upgrade/check on an empty disposable PostgreSQL database, SQLite compatibility where supported, restart/rollback/history preservation and affected concurrency cases |
| API contract | Python checks, generated-contract drift check and relevant API/browser tests |
| Browser behavior | ESLint, TypeScript, Vitest, bundle verifier tests and production build |
| Packaging/process lifecycle | Conventional wheel verifier and installed-process checks outside the checkout; relevant Stop, signal, timeout, restart and child cleanup tests |
| CI/runner | Runner/sharding tests, actual selection inspection and required aggregate behavior; exact-revision CI before integration closeout |

Start focused, fix failures, then run the appropriate broader gate. Do not rerun
multi-hour retained suites merely to validate document edits. Do not substitute
instrumented diagnostics for the required unprofiled acceptance run.

Semantic conversion changes also require `tests/unit/test_personal_semantic_stopiteration.py`
alongside `test_personal_semantic_dispatch.py` and the canonical/codec suites.
These independent-oracle tests cover generator exception chaining and temporary
release while a traceback is alive; matching normal values and hashes is insufficient.
The standard `test_personal_*` selection includes them.

## Static checks

Run the architecture checker before importing project code. It is standard
library only and scans import direction and pure-code boundaries statically:

```sh
"$AQT_PYTHON" -I -B scripts/check_personal_architecture.py
"$AQT_PYTHON" -m ruff format --check .
"$AQT_PYTHON" -m ruff check .
"$AQT_PYTHON" -m mypy apps packages
env -i PATH="$(dirname "$AQT_PYTHON"):/usr/bin:/bin" \
  PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 \
  "$AQT_PYTHON" -B -m scripts.generate_api_contracts --check
git diff --check
```

The contract generator constructs a local in-memory API schema and compares
`docs/api/openapi.json` and `apps/web/src/api/schema.generated.ts`. Regenerate
only for an intentional contract change by omitting `--check`; inspect both
generated diffs. Formatting changes use `"$AQT_PYTHON" -m ruff format <files>`.
The repository has no separate frontend formatter command.

`make architecture-check`, `make backend-check`, `make api-contracts-check`,
`make frontend-check`, `make personal-check`, and `make check` are maintained
convenience targets. The latter includes the complete selected Python suite,
browser checks and Compose model check. Inspect their tool/environment behavior
before using them in a preserved runtime.

## Unit and selected integration tests

Example focused offline command (change the explicit test paths to the affected
area; do not replace this with unbounded `pytest tests`):

```sh
env -i PATH="$(dirname "$AQT_PYTHON"):/usr/bin:/bin" \
  PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC \
  "$AQT_PYTHON" -B -m pytest -q -p no:cacheprovider \
  tests/unit/test_personal_ci_runner.py \
  tests/unit/test_personal_architecture.py
```

The full current foundation and retained financial scope is defined by explicit
lists and patterns in `scripts/run_personal_tests.py`:

```sh
"$AQT_PYTHON" -B scripts/run_personal_tests.py
```

This includes financial reducers, accounting, risk/reservations, uncertain
submission recovery, OAuth/data/time contracts, research reports/workflows and
continuous simulation/reconciliation. The runner preserves pytest's exit code.
The suite can be lengthy; it is not a quick smoke check. PostgreSQL-only tests
skip without an explicit URL. Report those skips as missing evidence.

For one of the 16 deterministic CI shards:

```sh
"$AQT_PYTHON" -B scripts/run_personal_tests.py --shard-count 16 --shard-index 0
```

Indices are zero-based. Every selected node belongs to one SHA-256 shard and
retains collection order within that shard. Running one shard is partial
evidence. The CI aggregate requires foundations and all 16 shards to succeed.

## PostgreSQL and migrations

The following URL is the disposable local CI service identity. Run these only
after establishing that this endpoint is a newly owned test database; the
commands do not create or identify a safe database automatically:

```sh
env -i PATH="$(dirname "$AQT_PYTHON"):/usr/bin:/bin" \
  PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 \
  AQT_DATABASE_URL=postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test \
  "$AQT_PYTHON" -B -m alembic upgrade head
env -i PATH="$(dirname "$AQT_PYTHON"):/usr/bin:/bin" \
  PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 \
  AQT_DATABASE_URL=postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test \
  "$AQT_PYTHON" -B -m alembic check
"$AQT_PYTHON" -B scripts/run_personal_tests.py \
  --postgres-url postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test
```

CI provisions PostgreSQL 16 separately for foundations and each shard. Test
fixtures cover serialized risk capacity, coordinator lease races, concurrent
publication and transactional persistence. Do not run concurrent local suites
against the same fixture database or use `make migrate` with an ambient runtime
DSN. Shut down only services/processes created for the test and retain failure
evidence before cleanup where appropriate.

## Simulation, backtests and process tests

The suite exercises golden arithmetic compatibility, actual causal engine
outputs, independent economic/report oracles, synthetic datasets, benchmark
alignment, costs, settlement, corporate actions, replay, observed accounting,
uncertain submission, resource limits and crash/restart/Stop behavior.
Relevant families include `test_personal_*`, `test_research_*`,
`test_retained_research_*`, `test_continuous_*`, `test_daily_*`,
`test_stateful_venue*` and `test_venue_*`.

Required retained restoration uses its unchanged lease, time, CPU, memory and
output limits. The optional Linux failure-only profile in CI records bounded
code metadata/timings; a diagnostic pass cannot erase an unprofiled failure.
Record financial/source/venue/artifact preservation and complete owned process
cleanup for retained-history acceptance.

The current conventional wheel checks are encoded in
`.github/workflows/ci.yml` and these scripts:

```sh
"$AQT_PYTHON" -B scripts/verify_personal_wheel.py /absolute/new-wheel-directory
"$AQT_PYTHON" -B scripts/verify_personal_research_process.py \
  --python /absolute/installed-environment/bin/python \
  --output-dir /absolute/new-process-check-directory
"$AQT_PYTHON" -B scripts/verify_personal_research_jobs.py \
  --python /absolute/installed-environment/bin/python \
  --output-dir /absolute/new-workflow-check-directory
```

These require the built/installed artifact and a new writable output directory;
do not silently substitute imports from the source checkout. CI also validates
the installed HALTED simulation CLI, the bounded synthetic worker and an exact
flat-fixture economic result outside the checkout. The default conventional
wheel excludes the opt-in native qualification path.

## Browser and Compose checks

With locked browser dependencies installed and no private environment files in
the checkout:

```sh
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test --run
pnpm --dir apps/web bundle:test
pnpm --dir apps/web build
docker compose --env-file /dev/null -f infra/compose/compose.yaml config --quiet
```

Vitest uses jsdom and Testing Library; browser/API calls are mocked in the test
suite. Production build includes `bundle:check` for emitted bundle boundaries.
The Compose command validates definitions without starting services. Vite loads
environment files in its config; keep provider secrets out of the frontend
environment. `pnpm test` without `--run` is interactive/watch mode.

## Paper, connected and historical/native qualification

No standard validation command submits provider orders. Broker-shaped fixtures
and fake transports test request admission, identity, limits, decoding,
reconciliation and no-effect failures. They do not establish current broker
semantics or paper/live readiness. Paper account enrollment, read-only provider
qualification, OAuth acquisition/renewal, data capture and deployment preflight
have explicit access/retention/approval prerequisites in their runbooks.

`make dev`, `make db`, `make trader`, provider/capture commands,
`trusted-time-*`, `make legacy-test` and manual historical native workflow
dispatch are not ordinary offline test setup. The full historical suite has
separate native build, exact-manifest, resource, platform and launcher
prerequisites. Preserve those checks rather than weakening them to make the
current personal profile appear ready. Refer to the relevant historical
runbooks only when work actually targets those systems.

## Important gaps and evidence limits

- Current Wave 4 acceptance status belongs in `STATUS.md` and the exact-revision
  evidence records. Previous local passes do not close a failing Linux gate.
- Real captured-session decision/replay parity, account/provider semantics,
  calendar/clock qualification and initializer acceptance are distinct from
  synthetic contract tests and remain subject to their recorded blockers.
- Optional Tiingo selection and original Chrony conversion tests prove mechanical
  matching/ownership only. HTTP fixtures replace credential and socket operations;
  a `provider_https_read` result in those tests does not qualify actual provider
  access. Include cleanup mutation/expiry as well as pre-dispatch rejection when
  changing a concrete transport.
- Without disposable PostgreSQL, concurrency and PostgreSQL behavior are
  unverified; without Linux, Linux resource/process behavior is unverified.
- Browser tests are jsdom component/integration tests, not full browser-driven
  end-to-end validation against a running API/worker.
- Pytest's configured defaults enforce strict config/markers, but no global
  timeout or network-denial plugin is configured. The runner's sanitized
  environment is not an OS network sandbox. Use mocked transports and existing
  bounded process owners; investigate hangs instead of raising safety limits.
- The selected runner is intentional rather than every historical test. Any new
  regression outside its patterns must be added explicitly to remain covered.
  The September 26 repair adds the 14 previously excluded shard-hook tests to
  that selection and points their preserved historical workflow assertion at
  `legacy-native.yml`. Runner and shard regressions pass together (32 cases).
- There is no declared Python coverage threshold. The frontend advertises
  `test:coverage` but does not declare a Vitest coverage-provider package; the
  supported CI gate is `test --run`, not an assumed coverage result.
- No backtest, paper result or historical return implies future profitability.
