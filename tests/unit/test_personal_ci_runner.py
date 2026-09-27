"""The personal CI runner preserves isolation and makes every shard required."""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts import run_personal_tests as runner

ROOT = Path(__file__).resolve().parents[2]
POSTGRES = "postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test"


def _invoke(monkeypatch, args, *, exit_code=0):
    calls = []

    def capture(command, **options):
        calls.append((command, options))
        return subprocess.CompletedProcess(command, exit_code)

    monkeypatch.setattr(sys, "argv", ["run_personal_tests.py", *args])
    monkeypatch.setattr(runner.subprocess, "run", capture)
    return runner.main(), calls


@pytest.mark.parametrize("postgres", [False, True])
def test_default_selection_is_isolated_and_propagates_pytest_exit(monkeypatch, postgres):
    monkeypatch.setenv("AQT_DATABASE_URL", "unrelated-operational-database")
    monkeypatch.setenv("CI_TEST_SENTINEL", "must-not-be-forwarded")
    args = ["--postgres-url", POSTGRES] if postgres else []
    result, calls = _invoke(monkeypatch, args, exit_code=7)
    assert result == 7 and len(calls) == 1
    command, options = calls[0]
    assert command[:8] == [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--basetemp",
    ]
    assert options["cwd"] == ROOT and options["check"] is False
    env = options["env"]
    assert env == {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TMPDIR": env["TMPDIR"],
        "TZ": "UTC",
    }
    assert command[8] == str(Path(env["TMPDIR"]) / "pytest")
    targets = [item for item in command if item.startswith("tests/")]
    assert targets == sorted(set(targets))
    assert {
        "tests/unit/test_personal_ci_runner.py",
        "tests/unit/test_pytest_sharding.py",
        "tests/unit/test_accounting.py",
        "tests/unit/test_attempt_resolved_fingerprint.py",
        "tests/integration/test_continuous_session_acceptance.py",
        "tests/integration/test_continuous_postgres_competing_publication.py",
        "tests/integration/test_phase2_postgres_exit.py::test_two_owners_racing_for_first_coordinator_lease_have_one_winner",
        "tests/integration/test_phase2_postgres_exit.py::test_same_owner_conditional_generation_race_advances_only_once",
    } <= set(targets)
    assert "--aqt-shard-count" not in command and "--aqt-shard-index" not in command
    if postgres:
        assert command[-2:] == ["--aqt-test-postgres-url", POSTGRES]
    else:
        assert "--aqt-test-postgres-url" not in command


@pytest.mark.parametrize("count,index", [(1, 0), (16, 0), (16, 15), (32, 31)])
def test_valid_shards_forward_to_original_pytest_hook(monkeypatch, count, index):
    result, calls = _invoke(
        monkeypatch,
        ["--postgres-url", POSTGRES, "--shard-count", str(count), "--shard-index", str(index)],
    )
    assert result == 0 and len(calls) == 1
    assert calls[0][0][-6:] == [
        "--aqt-test-postgres-url",
        POSTGRES,
        "--aqt-shard-count",
        str(count),
        "--aqt-shard-index",
        str(index),
    ]


@pytest.mark.parametrize(
    "args",
    [
        ["--shard-count", "16"],
        ["--shard-index", "0"],
        ["--shard-count", "0", "--shard-index", "0"],
        ["--shard-count", "-1", "--shard-index", "0"],
        ["--shard-count", "33", "--shard-index", "0"],
        ["--shard-count", "16", "--shard-index", "-1"],
        ["--shard-count", "16", "--shard-index", "16"],
        ["--shard-count", "nan", "--shard-index", "0"],
        ["--shard-count", "16", "--shard-index", "1.5"],
    ],
)
def test_invalid_shards_never_start_pytest(monkeypatch, args):
    calls = []
    monkeypatch.setattr(sys, "argv", ["run_personal_tests.py", *args])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: calls.append((a, kw)))
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2 and calls == []


def _jobs():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]


def test_matrix_preserves_explicit_pg_and_required_foundations_and_browser_work():
    jobs = _jobs()
    foundation = jobs["backend-foundations"]
    matrix = jobs["backend-tests"]
    assert matrix["needs"] == "backend-foundations"
    assert matrix["strategy"] == {
        "fail-fast": False,
        "max-parallel": 4,
        "matrix": {"shard_index": list(range(16))},
    }
    assert "continue-on-error" not in matrix
    assert matrix["services"] == foundation["services"]
    assert matrix["services"]["postgres"]["image"] == "postgres:16-alpine"
    assert "AQT_TEST_POSTGRES_URL" not in matrix["env"]
    invocation = matrix["steps"][-1]["run"]
    assert "scripts/run_personal_tests.py" in invocation
    assert f"--postgres-url {POSTGRES}" in invocation
    assert "--shard-count 16" in invocation
    assert "--shard-index ${{ matrix.shard_index }}" in invocation
    assert matrix["steps"][:4] == foundation["steps"][:4]
    for name in (
        "Formatting, lint, types, and API contracts",
        "Check migrations against the disposable database",
        "Build conventional wheel with pinned build dependencies",
        "Verify and run installed wheel outside source checkout",
        "Exercise installed durable research workflow with locked runtime dependencies",
        "Validate historical Compose definitions without activation",
    ):
        matches = [
            step
            for job in jobs.values()
            for step in job.get("steps", [])
            if step.get("name") == name
        ]
        assert len(matches) == 1 and matches[0] in foundation["steps"]
    assert [step["run"] for step in jobs["frontend"]["steps"] if "run" in step] == [
        "pnpm install --frozen-lockfile",
        "pnpm lint",
        "pnpm typecheck",
        "pnpm test --run",
        "pnpm bundle:test",
        "pnpm build",
    ]


@pytest.mark.parametrize("errexit", [False, True])
def test_required_aggregate_rejects_every_non_success_without_shell_assumptions(errexit):
    aggregate = _jobs()["backend"]
    assert aggregate["name"] == "Standard Python foundations and retained financial regressions"
    assert aggregate["if"] == "${{ always() }}"
    assert aggregate["needs"] == ["backend-foundations", "backend-tests"]
    assert "continue-on-error" not in aggregate and len(aggregate["steps"]) == 1
    step = aggregate["steps"][0]
    assert step["env"] == {
        "FOUNDATIONS_RESULT": "${{ needs.backend-foundations.result }}",
        "TESTS_RESULT": "${{ needs.backend-tests.result }}",
    }
    states = ("success", "failure", "cancelled", "skipped", "", "unexpected")
    for foundation in states:
        for tests in states:
            result = subprocess.run(
                ["/bin/bash", *(["-e"] if errexit else []), "-c", step["run"]],
                env={"FOUNDATIONS_RESULT": foundation, "TESTS_RESULT": tests},
                capture_output=True,
                timeout=2,
                check=False,
            )
            assert (result.returncode == 0) == (foundation == tests == "success")
