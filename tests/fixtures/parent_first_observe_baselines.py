"""Public pre-diagnostic Source bytes as inert portable regression oracles.

These constants never execute worker, SQL, workflow, Git or provider code.
"""

WORKER_BASELINE_BYTES = (
    b'"""Fixed supervised child restores real halted signed history fro'
    b"m SQLite.\n\nThe parent observes the actual child lease/control lif"
    b"ecycle through read-only\nSQLite probes. Canonical history and int"
    b'egrity remain the child\'s responsibility.\n"""\n\nimport json\nfrom p'
    b"athlib import Path\nfrom time import thread_time_ns\n\nfrom apps.tra"
    b"der.continuous_process_lifecycle import SqlContinuousParentProbe\n"
    b"from packages.application import continuous_process as process_mo"
    b"dule\nfrom packages.application.continuous_process import Continuo"
    b"usProcessSupervisor\nfrom packages.application.personal_runtime im"
    b"port LocalInstanceGuard\nfrom tests.fixtures.continuous_process_ob"
    b"servation import ChildObservationDiagnostic\nfrom tests.fixtures.l"
    b"ifecycle_failure_output import (\n    create_parent_diagnostics,\n "
    b"   emit_parent_failure_line,\n    wrap_already_constructed,\n)\nfrom"
    b" tests.integration import test_continuous_simulation_factory as f"
    b"actory_fixture\n\nconfigured = factory_fixture.configured\n\n\ndef tes"
    b"t_fixed_worker_runs_real_halted_restore_and_restarts_with_identic"
    b"al_financial_history(\n    configured,\n    monkeypatch,\n):\n    fix"
    b"ture, config = configured\n    pair = fixture[0]\n    factory_fixtu"
    b"re.install_initial_signed_assignment(fixture)\n    original = pair"
    b".account.restore(pair.base.scope)\n    counts = pair.counts()\n    "
    b"factory_fixture.release(fixture)\n    request = factory_fixture.re"
    b"quest_for(fixture, config)\n    private = Path(config.database_pat"
    b'h).parent / "supervised"\n    private.mkdir(mode=0o700)\n    superv'
    b"isor = ContinuousProcessSupervisor(artifact_directory=private)\n  "
    b'  with LocalInstanceGuard(private / "instance.lock") as lock:\n   '
    b"     results = []\n        parent_diagnostics = create_parent_diag"
    b"nostics(native_timing=True)\n        for iteration in range(1, 3):"
    b"\n            diagnostic = ChildObservationDiagnostic(\n           "
    b"     process_module._observe_child,\n                deadline_code"
    b"=process_module._observe_linux_child.__code__,\n                th"
    b"read_clock_ns=thread_time_ns,\n            )\n            with monk"
    b"eypatch.context() as observation_patch:\n                observati"
    b'on_patch.setattr(process_module, "_observe_child", diagnostic.obs'
    b"erve)\n                outcome = supervisor.run(\n                 "
    b"   request,\n                    lock_descriptor=lock.fileno(),\n  "
    b"                  stop_requested=lambda: False,\n                 "
    b"   lifecycle=wrap_already_constructed(\n                        Sq"
    b"lContinuousParentProbe(request),\n                        diagnost"
    b"ics=parent_diagnostics,\n                        iteration=iterati"
    b"on,\n                    ),\n                )\n            try:\n   "
    b'             assert outcome.status == "completed", outcome.reason'
    b"\n            except AssertionError:\n                # The origina"
    b"l supervisor and its finally cleanup have returned;\n             "
    b"   # only bounded static metadata is added to a failed assertion."
    b'\n                print(\n                    "AQT_CHILD_OBSERVATIO'
    b'N_DIAGNOSTIC "\n                    + json.dumps(diagnostic.summar'
    b"y(iteration=iteration), sort_keys=True)\n                )\n       "
    b"         try:  # noqa: SIM105 - isolate metadata without a new co"
    b"ntext manager\n                    emit_parent_failure_line(parent"
    b"_diagnostics, iteration=iteration)\n                except BaseExc"
    b"eption:\n                    pass\n                raise\n          "
    b"  assert outcome.receipt is not None\n            payload = outcom"
    b"e.receipt.path.read_bytes()\n            assert len(payload) == ou"
    b"tcome.receipt.byte_count\n            results.append(json.loads(pa"
    b"yload))\n    assert results[0] == results[1]\n    assert results[0]"
    b'["checkpoint_sha256"] == original.checkpoint.semantic_sha256\n    '
    b'assert results[0]["commit_sha256"] == original.receipt.commit.sem'
    b'antic_sha256\n    assert results[0]["status"] == "restored"\n    as'
    b"sert pair.counts() == counts\n"
)
WORKER_BASELINE_SHA256 = "31764f247e838d39f7278718441ac15a378bf5371a7991be89a9ecef31240c13"

WORKFLOW_BASELINE_BYTES = (
    b"name: Personal profile CI\n\non:\n  pull_request:\n  push:\n    branch"
    b"es: [main]\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\nc"
    b"oncurrency:\n  group: ci-${{ github.workflow }}-${{ github.ref }}\n"
    b"  cancel-in-progress: true\n\njobs:\n  backend-foundations:\n    name"
    b": Standard Python foundations and installed-wheel checks\n    runs"
    b"-on: ubuntu-latest\n    timeout-minutes: 30\n    env:\n      PYTHOND"
    b'ONTWRITEBYTECODE: "1"\n      SOURCE_DATE_EPOCH: "0"\n      AQT_ENVI'
    b"RONMENT: local\n    services:\n      postgres:\n        image: postg"
    b"res:16-alpine\n        env:\n          POSTGRES_USER: autoquant\n   "
    b"       POSTGRES_PASSWORD: autoquant\n          POSTGRES_DB: autoqu"
    b'ant_test\n        ports: ["5432:5432"]\n        options: >-\n       '
    b'   --health-cmd "pg_isready -U autoquant -d autoquant_test"\n     '
    b"     --health-interval 2s --health-timeout 3s --health-retries 20"
    b"\n    steps:\n      - uses: actions/checkout@v7\n      - uses: astra"
    b"l-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b # v8.1.0\n "
    b'       with:\n          python-version: "3.12.13"\n          versio'
    b'n: "0.11.28"\n          enable-cache: true\n          cache-depende'
    b"ncy-glob: uv.lock\n      - name: Check architecture before importi"
    b"ng project code\n        run: uv run --isolated --no-project --no-"
    b"config --offline --python 3.12 python -I -B scripts/check_persona"
    b"l_architecture.py\n      - name: Install locked dependencies witho"
    b"ut executing project build code\n        run: uv sync --all-groups"
    b" --locked --no-install-project --no-build\n      - name: Formattin"
    b"g, lint, types, and API contracts\n        run: |\n          .venv/"
    b"bin/ruff format --check .\n          .venv/bin/ruff check .\n      "
    b"    .venv/bin/mypy apps packages\n          .venv/bin/python -B -m"
    b" scripts.generate_api_contracts --check\n      - name: Check migra"
    b"tions against the disposable database\n        env:\n          AQT_"
    b"DATABASE_URL: postgresql+psycopg://autoquant:autoquant@localhost:"
    b"5432/autoquant_test\n        run: |\n          .venv/bin/alembic up"
    b"grade head\n          .venv/bin/alembic check\n      - name: Build "
    b"conventional wheel with pinned build dependencies\n        run: uv"
    b" build --wheel --no-sources --build-constraints build_support/nat"
    b'ive_build_constraints.txt --require-hashes --out-dir "$RUNNER_TEM'
    b'P/personal-wheel"\n      - name: Verify and run installed wheel ou'
    b"tside source checkout\n        run: |\n          .venv/bin/python -"
    b'B scripts/verify_personal_wheel.py "$RUNNER_TEMP/personal-wheel"\n'
    b'          uv venv "$RUNNER_TEMP/personal-installed" --python 3.12'
    b'\n          uv pip install --python "$RUNNER_TEMP/personal-install'
    b'ed/bin/python" --no-deps "$RUNNER_TEMP"/personal-wheel/*.whl\n    '
    b'      cd "$RUNNER_TEMP"\n          env -i PATH=/usr/bin:/bin "$RUN'
    b'NER_TEMP/personal-installed/bin/autoquant-personal-simulation" --'
    b'instance-lock "$RUNNER_TEMP/personal-runtime.lock" --once\n       '
    b'   env -i PATH=/usr/bin:/bin "$RUNNER_TEMP/personal-installed/bin'
    b'/autoquant-worker" --fixture flat --fixture-sessions 12 --warmup '
    b'3 --lookback 3 --max-seconds 30 --max-output-mib 16 --output "$RU'
    b'NNER_TEMP/installed-research.json"\n          "$RUNNER_TEMP/person'
    b"al-installed/bin/python\" -c 'import json,sys; from decimal import"
    b' Decimal; r=json.load(open(sys.argv[1]))["report"]; m={x["name"]:'
    b'x for x in r["metrics"]}; assert r["status"]=="completed" and Dec'
    b'imal(m["ending_equity"]["value"])==Decimal("9998.56"); assert m["'
    b'annualized_return"]["value"] is None; assert len(r["source"]["exe'
    b'cutions"])==1\' "$RUNNER_TEMP/installed-research.json"\n          "'
    b'$RUNNER_TEMP/personal-installed/bin/python" -B "$GITHUB_WORKSPACE'
    b'/scripts/verify_personal_research_process.py" --python "$RUNNER_T'
    b'EMP/personal-installed/bin/python" --output-dir "$RUNNER_TEMP/ins'
    b'talled-research-process-checks"\n      - name: Exercise installed '
    b"durable research workflow with locked runtime dependencies\n      "
    b"  run: |\n          uv export --quiet --locked --no-dev --no-emit-"
    b'project --format requirements.txt --output-file "$RUNNER_TEMP/per'
    b'sonal-runtime-requirements.txt"\n          uv venv "$RUNNER_TEMP/r'
    b'esearch-installed" --python 3.12\n          uv pip sync --python "'
    b'$RUNNER_TEMP/research-installed/bin/python" --require-hashes --on'
    b'ly-binary :all: "$RUNNER_TEMP/personal-runtime-requirements.txt"\n'
    b'          uv pip install --python "$RUNNER_TEMP/research-installe'
    b'd/bin/python" --no-deps "$RUNNER_TEMP"/personal-wheel/*.whl\n     '
    b'     cd "$RUNNER_TEMP"\n          env -i PATH=/usr/bin:/bin "$RUNN'
    b'ER_TEMP/research-installed/bin/python" -I -B "$GITHUB_WORKSPACE/s'
    b'cripts/verify_personal_research_jobs.py" --python "$RUNNER_TEMP/r'
    b'esearch-installed/bin/python" --output-dir "$RUNNER_TEMP/installe'
    b'd-durable-research-checks"\n      - name: Validate historical Comp'
    b"ose definitions without activation\n        run: docker compose --"
    b"env-file /dev/null -f infra/compose/compose.yaml config --quiet\n\n"
    b"  backend-tests:\n    name: Retained financial regressions (shard "
    b"index ${{ matrix.shard_index }} of 16)\n    needs: backend-foundat"
    b"ions\n    runs-on: ubuntu-latest\n    # CI budget only; final Linux"
    b" shard timings still require qualification.\n    timeout-minutes: "
    b"60\n    strategy:\n      fail-fast: false\n      max-parallel: 4\n   "
    b"   matrix:\n        shard_index: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10"
    b', 11, 12, 13, 14, 15]\n    env:\n      PYTHONDONTWRITEBYTECODE: "1"'
    b'\n      SOURCE_DATE_EPOCH: "0"\n      AQT_ENVIRONMENT: local\n    se'
    b"rvices:\n      postgres:\n        image: postgres:16-alpine\n       "
    b" env:\n          POSTGRES_USER: autoquant\n          POSTGRES_PASSW"
    b"ORD: autoquant\n          POSTGRES_DB: autoquant_test\n        port"
    b's: ["5432:5432"]\n        options: >-\n          --health-cmd "pg_i'
    b'sready -U autoquant -d autoquant_test"\n          --health-interva'
    b"l 2s --health-timeout 3s --health-retries 20\n    steps:\n      - u"
    b"ses: actions/checkout@v7\n      - uses: astral-sh/setup-uv@0880764"
    b"7e7069bb48b6ef5acd8ec9567f424441b # v8.1.0\n        with:\n        "
    b'  python-version: "3.12.13"\n          version: "0.11.28"\n        '
    b"  enable-cache: true\n          cache-dependency-glob: uv.lock\n   "
    b"   - name: Check architecture before importing project code\n     "
    b"   run: uv run --isolated --no-project --no-config --offline --py"
    b"thon 3.12 python -I -B scripts/check_personal_architecture.py\n   "
    b"   - name: Install locked dependencies without executing project "
    b"build code\n        run: uv sync --all-groups --locked --no-instal"
    b"l-project --no-build\n      - name: Exact retained suite shard wit"
    b"h an explicit disposable PostgreSQL database\n        run: >-\n    "
    b"      .venv/bin/python -B scripts/run_personal_tests.py\n         "
    b" --postgres-url postgresql+psycopg://autoquant:autoquant@localhos"
    b"t:5432/autoquant_test\n          --shard-count 16\n          --shar"
    b"d-index ${{ matrix.shard_index }}\n\n  retained-restore-profile:\n  "
    b"  name: Diagnostic retained restore profile (failure stays failur"
    b"e)\n    needs: [backend-foundations, backend-tests]\n    # Collect "
    b"Linux costs only when the required, unprofiled regression gate fa"
    b"iled.\n    # This job neither replaces that gate nor participates "
    b"in its aggregate.\n    if: ${{ always() && needs.backend-foundatio"
    b"ns.result == 'success' && needs.backend-tests.result == 'failure'"
    b" }}\n    runs-on: ubuntu-latest\n    timeout-minutes: 20\n    env:\n "
    b'     PYTHONDONTWRITEBYTECODE: "1"\n      SOURCE_DATE_EPOCH: "0"\n  '
    b"    AQT_ENVIRONMENT: local\n    steps:\n      - uses: actions/check"
    b"out@v7\n      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd"
    b"8ec9567f424441b # v8.1.0\n        with:\n          python-version: "
    b'"3.12.13"\n          version: "0.11.28"\n          enable-cache: tr'
    b"ue\n          cache-dependency-glob: uv.lock\n      - name: Check a"
    b"rchitecture before importing project code\n        run: uv run --i"
    b"solated --no-project --no-config --offline --python 3.12 python -"
    b"I -B scripts/check_personal_architecture.py\n      - name: Install"
    b" locked dependencies without executing project build code\n       "
    b" run: uv sync --all-groups --locked --no-install-project --no-bui"
    b"ld\n      - name: Profile the original retained restore test with "
    b'unchanged limits\n        run: |\n          profile_directory="$RUN'
    b'NER_TEMP/retained-restore-profile"\n          mkdir "$profile_dire'
    b'ctory"\n          set +e\n          env -i PATH="$GITHUB_WORKSPACE/'
    b'.venv/bin:/usr/bin:/bin" \\\n            PYTHONPATH="$GITHUB_WORKSP'
    b'ACE" PYTHONDONTWRITEBYTECODE=1 \\\n            PYTEST_DISABLE_PLUGI'
    b'N_AUTOLOAD=1 TZ=UTC TMPDIR="$RUNNER_TEMP" \\\n            AQT_RETAI'
    b'NED_RESTORE_PROFILE_PATH="$profile_directory/profile.json" \\\n    '
    b"        .venv/bin/python -B -m pytest -q -p no:cacheprovider \\\n  "
    b'          --basetemp "$RUNNER_TEMP/retained-restore-profile-fixtu'
    b're" \\\n            tests/integration/test_continuous_simulation_fa'
    b"ctory_outcome.py::test_actual_signed_retained_outcome_restores_wi"
    b"th_original_utc_and_lease\n          test_exit=$?\n          set -e"
    b'\n          printf \'{"schema":"retained-diagnostic-test-exit/1","d'
    b'iagnostic_only":true,"pytest_exit_code":%s}\\n\' "$test_exit" > "$p'
    b"rofile_directory/test-exit.json\"\n          printf 'Retained resto"
    b"re diagnostic pytest exit: **%s**. Instrumented evidence only; th"
    b"e required unprofiled result remains authoritative.\\n' \"$test_exi"
    b't" >> "$GITHUB_STEP_SUMMARY"\n          exit "$test_exit"\n      - '
    b"name: Upload only sanitized profile and exact diagnostic test exi"
    b"t\n        if: ${{ always() }}\n        uses: actions/upload-artifa"
    b"ct@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\n        with:\n  "
    b"        name: retained-restore-profile-${{ github.run_id }}-${{ g"
    b"ithub.run_attempt }}\n          path: |\n            ${{ runner.tem"
    b"p }}/retained-restore-profile/profile.json\n            ${{ runner"
    b".temp }}/retained-restore-profile/test-exit.json\n          if-no-"
    b"files-found: error\n          retention-days: 7\n      - name: Requ"
    b"ire a profile report from the diagnostic\n        if: ${{ always()"
    b' }}\n        run: |\n          if [ ! -f "$RUNNER_TEMP/retained-res'
    b"tore-profile/profile.json\" ]; then\n            printf 'No retaine"
    b"d restore profile was produced. The diagnostic is incomplete.\\n' "
    b'>> "$GITHUB_STEP_SUMMARY"\n            exit 1\n          fi\n\n  back'
    b"end:\n    name: Standard Python foundations and retained financial"
    b" regressions\n    if: ${{ always() }}\n    needs: [backend-foundati"
    b"ons, backend-tests]\n    runs-on: ubuntu-latest\n    timeout-minute"
    b"s: 5\n    steps:\n      - name: Require every foundation and test s"
    b"hard to succeed\n        env:\n          FOUNDATIONS_RESULT: ${{ ne"
    b"eds.backend-foundations.result }}\n          TESTS_RESULT: ${{ nee"
    b'ds.backend-tests.result }}\n        run: |\n          if [ "$FOUNDA'
    b'TIONS_RESULT" != success ] || [ "$TESTS_RESULT" != success ]; the'
    b"n\n            exit 1\n          fi\n\n  frontend:\n    name: Browser "
    b"regressions\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n  "
    b"  defaults:\n      run:\n        working-directory: apps/web\n    st"
    b"eps:\n      - uses: actions/checkout@v7\n      - uses: pnpm/action-"
    b"setup@v6\n        with:\n          package_json_file: apps/web/pack"
    b"age.json\n      - uses: actions/setup-node@v6\n        with:\n      "
    b'    node-version: "22"\n          cache: pnpm\n          cache-depe'
    b"ndency-path: apps/web/pnpm-lock.yaml\n      - run: pnpm install --"
    b"frozen-lockfile\n      - run: pnpm lint\n      - run: pnpm typechec"
    b"k\n      - run: pnpm test --run\n      - run: pnpm bundle:test\n    "
    b"  - run: pnpm build\n"
)
WORKFLOW_BASELINE_SHA256 = "1b7ad1f7a8f5cf467759a60dc09e2983e150f1d2026704f4f808100f7709d8a0"
