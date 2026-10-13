"""Fixed bounded diagnostic route; never actual worker or financial acceptance.

Only the admitted worker FunctionDef executes with synthetic inert ports. Private
native replacements are finite unit seams, not public profiler/clock callbacks.
"""

import ast
import hashlib
import json
import stat
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from tests.fixtures import parent_first_observe_profile as profile_module
from tests.fixtures.parent_first_observe_baselines import (
    WORKFLOW_BASELINE_BYTES,
    WORKFLOW_BASELINE_SHA256,
)
from tests.unit.test_personal_worker_parent_diagnostic_wiring import (
    Harness,
    admitted_function,
    assert_cleanup,
    current_source,
)

ENV_NAME = "AQT_PARENT_FIRST_OBSERVE_PROFILE_PATH"
REPORT_NAME = "parent-probe-first-observe.json"
BOUNDED_SCHEMA = "parent-probe-iteration2-first-observe-static-cprofile/2"
BOUNDED_SELECTION = (
    "Full native entry validation precedes the union of top32 inclusive and self-time "
    "entries overall and project-only, at most128 rows. Omitted rows are unknown; ordinals "
    "distinguish equal static labels. Output is at most49152 bytes; emitted limits do not "
    "bound native profiler storage, which retains code/stat entries until released."
)


def _projection_leaf():
    return None


def _bounded(monkeypatch, stats=None):
    events = []

    class NativeStub:
        def enable(self):
            events.append("enable")

        def disable(self):
            events.append("disable")

        def getstats(self):
            events.append("getstats")
            return [] if stats is None else stats

        def clear(self):
            events.append("clear")

    owner = profile_module.create_bounded_first_observe_profile(enabled=True)
    owner._factory = owner._profile_type = NativeStub
    owner._getprofile = owner._gettrace = lambda: None
    owner._get_tool = lambda tool: None
    owner._get_events = lambda tool: 0
    return owner, events


def _selection_material():
    entries = []
    for code, total, own in (
        ("<built-in method len>", 40.0, 0.2),
        ("<built-in method sum>", 30.0, 5.0),
        (_projection_leaf.__code__, 20.0, 0.1),
        (_projection_leaf.__code__, 10.0, 4.0),
        ("<built-in method len>", 1.0, 0.0),
    ):
        entries.extend(
            profile_module._NativeEntry((code, 1, 0, total, own, None)) for _ in range(32)
        )
    return entries


def test_fixed_union_reaches_128_with_independent_ordinals_metrics_and_schema():
    report = profile_module._bounded_static_report(
        _selection_material(), Path(__file__).resolve().parents[2], True
    )
    assert profile_module.BOUNDED_TOP_ENTRIES == 32
    assert profile_module.BOUNDED_ROW_CAP == 128
    assert profile_module.BOUNDED_REPORT_CAP == 49152
    assert report["schema"] == BOUNDED_SCHEMA
    assert report["selection"] == BOUNDED_SELECTION
    assert report["stats_entries_considered"] == 160
    assert len(report["rows"]) == 128
    assert {row["stats_entry_ordinal"] for row in report["rows"]} == set(range(128))
    assert [row["stats_entry_ordinal"] for row in report["rows"]] == list(range(128))
    assert [row["inclusive_seconds"] for row in report["rows"]] == (
        [40.0] * 32 + [30.0] * 32 + [20.0] * 32 + [10.0] * 32
    )
    assert len((json.dumps(report, indent=2, allow_nan=False) + "\n").encode()) <= 49152
    assert all(type(value) in (str, int, float) for row in report["rows"] for value in row.values())
    assert profile_module.ROW_CAP == 512 and profile_module.REPORT_CAP == 1_000_000


@pytest.mark.parametrize("field", ["code", "calls", "recursive", "total", "self"])
def test_low_ranked_malformed_native_entry_rejects_before_smaller_selection(field):
    values = ["<built-in method len>", 1, 0, 0.001, 0.0, None]
    offsets = {"code": 0, "calls": 1, "recursive": 2, "total": 3, "self": 4}
    invalid = {"code": object(), "calls": -1, "recursive": 2, "total": float("nan"), "self": -1.0}
    values[offsets[field]] = invalid[field]
    entries = _selection_material()
    entries.append(profile_module._NativeEntry(tuple(values)))
    with pytest.raises(ValueError, match="PARENT_PROFILE_NATIVE_STATS"):
        profile_module._bounded_static_report(entries, Path(__file__).resolve().parents[2], True)


@pytest.mark.parametrize("value", [None, 0, 1, "yes", [], object()])
def test_fixed_factory_requires_exact_bool_without_constructing(monkeypatch, value):
    def forbidden(*args, **kwargs):
        pytest.fail("bad opt-in constructed an owner")

    monkeypatch.setattr(profile_module, "FirstObserveProfile", forbidden)
    with pytest.raises(TypeError, match="PARENT_PROFILE_EXACT_BOOL"):
        profile_module.create_bounded_first_observe_profile(enabled=value)


def test_fixed_factory_default_performs_no_owner_or_native_calls(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("default constructed a helper")

    monkeypatch.setattr(profile_module, "FirstObserveProfile", forbidden)
    assert profile_module.create_bounded_first_observe_profile() is None
    assert profile_module.create_bounded_first_observe_profile(enabled=False) is None


@pytest.mark.parametrize("failed", [False, True])
def test_absent_worker_route_invokes_no_new_factory_validator_wrapper_export_or_emitter(
    tmp_path, monkeypatch, failed
):
    harness = Harness(
        tmp_path, statuses=("completed", "failed") if failed else ("completed", "completed")
    )

    def forbidden(*args, **kwargs):
        pytest.fail("absent opt-in invoked a new diagnostic")

    harness.profile_create = harness.profile_wrap = harness.require_profile_output = forbidden
    monkeypatch.setattr(profile_module, "_NativeProfile", forbidden)
    if failed:
        with pytest.raises(AssertionError) as caught:
            harness.execute(monkeypatch)
        assert caught.value is harness.pending and caught.value.args == ("probe_stalled",)
        assert len(harness.lines) == 2
        assert_cleanup(harness, caught.value)
    else:
        harness.execute(monkeypatch)
        assert harness.lines == []
        assert_cleanup(harness)
    assert not list(tmp_path.rglob(REPORT_NAME))
    assert len(harness.probes) == len(harness.wraps) == len(harness.runs) == 2
    assert (
        sum(isinstance(node, ast.Assert) for node in ast.walk(admitted_function(current_source())))
        == 8
    )


@pytest.mark.parametrize(
    "path_kind", ["empty", "relative", "wrong_basename", "public_parent", "existing", "symlink"]
)
def test_present_invalid_worker_optin_is_rejected_before_helper_and_original_fixture(
    tmp_path, monkeypatch, path_kind
):
    directory = tmp_path / "diagnostic"
    directory.mkdir(mode=0o700)
    output = directory / REPORT_NAME
    if path_kind == "empty":
        value = ""
    elif path_kind == "relative":
        value = REPORT_NAME
    elif path_kind == "wrong_basename":
        value = str(directory / "other.json")
    elif path_kind == "public_parent":
        directory.chmod(0o755)
        value = str(output)
    elif path_kind == "existing":
        output.write_bytes(b"do not overwrite")
        value = str(output)
    else:
        output.symlink_to(directory / "unused")
        value = str(output)
    harness = Harness(tmp_path)
    harness.profile_environment = {ENV_NAME: value}
    harness.require_profile_output = profile_module.require_first_observe_output

    def forbidden(*args, **kwargs):
        pytest.fail("invalid path constructed a helper")

    harness.profile_create = harness.profile_wrap = forbidden
    with pytest.raises((TypeError, ValueError), match="PARENT_PROFILE_OWNED_OUTPUT"):
        harness.execute(monkeypatch)
    assert harness.events == []
    if path_kind == "existing":
        assert output.read_bytes() == b"do not overwrite"
    elif path_kind == "symlink":
        assert output.is_symlink()


@pytest.mark.parametrize("failed", [False, True])
def test_explicit_worker_path_uses_real_bounded_finish_writer_and_preserves_assertion(
    tmp_path, monkeypatch, failed
):
    directory = tmp_path / "diagnostic"
    directory.mkdir(mode=0o700)
    output = directory / REPORT_NAME
    harness = Harness(
        tmp_path, statuses=("completed", "failed") if failed else ("completed", "completed")
    )
    owner, events = _bounded(monkeypatch)
    harness.profile_environment = {ENV_NAME: str(output)}
    harness.require_profile_output = profile_module.require_first_observe_output

    def create(*, enabled):
        assert enabled is True
        return owner

    harness.profile_create = create
    harness.profile_wrap = profile_module.wrap_first_observe_profile
    if failed:
        with pytest.raises(AssertionError) as caught:
            harness.execute(monkeypatch)
        assert caught.value is harness.pending
        assert (
            caught.value.__cause__ is harness.cause and caught.value.__context__ is harness.context
        )
        assert caught.value.__suppress_context__ is False
        assert len(harness.lines) == 3 and harness.lines[-1].startswith(profile_module.PREFIX)
        assert_cleanup(harness, caught.value)
    else:
        harness.execute(monkeypatch)
        assert_cleanup(harness)
    assert events == ["enable", "disable", "getstats", "clear"]
    raw = output.read_bytes()
    assert len(raw) <= 49152 and stat.S_IMODE(output.stat().st_mode) == 0o600
    report = json.loads(raw)
    assert report["schema"] == BOUNDED_SCHEMA and report["selection"] == BOUNDED_SELECTION
    assert report["observe_returned"] is True and report["rows"] == []
    assert raw == (json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode()
    assert owner.availability()["report_written"] is True


def _literal_report_with_size(size):
    # Handwritten admitted scalar report; digit padding changes only native count
    # values. Each integer stays below the stock4300-digit conversion ceiling.
    report = {
        "schema": BOUNDED_SCHEMA,
        "diagnostic_only": True,
        "iteration": 2,
        "observe_ordinal": 1,
        "scope": profile_module.SCOPE,
        "observe_started": True,
        "observe_returned": True,
        "stats_entries_considered": 128,
        "selection": BOUNDED_SELECTION,
        "rows": [
            {
                "stats_entry_ordinal": index,
                "group": "builtin",
                "file": "<builtin>",
                "line": 0,
                "function": "len",
                "calls": 1,
                "recursive_calls": 0,
                "inclusive_seconds": 0.0,
                "self_seconds": 0.0,
            }
            for index in range(128)
        ],
    }
    current = len((json.dumps(report, indent=2, allow_nan=False) + "\n").encode())
    assert current < size
    remaining = size - current
    for row in report["rows"]:
        extra = min(3000, remaining)
        row["calls"] = 10**extra
        remaining -= extra
        if remaining == 0:
            break
    assert remaining == 0
    assert len((json.dumps(report, indent=2, allow_nan=False) + "\n").encode()) == size
    return report


@pytest.mark.parametrize("extra", [0, 1])
def test_exact_49152_write_boundary_and_oversize_rejection_without_file(
    tmp_path, monkeypatch, extra
):
    tmp_path.chmod(0o700)
    owner, _ = _bounded(monkeypatch)
    owner._report = _literal_report_with_size(49152 + extra)
    owner._phase = "valid"
    output = tmp_path / REPORT_NAME
    if extra:
        with pytest.raises(ValueError, match="PARENT_PROFILE_OUTPUT_BOUND"):
            owner.write_after_cleanup(str(output))
        assert not output.exists() and owner.availability()["available"] is False
    else:
        assert owner.write_after_cleanup(str(output)) is True
        assert len(output.read_bytes()) == 49152


def test_bounded_oversize_preserves_explicit_pending_assertion_without_extra_file(
    tmp_path, monkeypatch
):
    owner, _ = _bounded(monkeypatch)
    owner._report, owner._phase = _literal_report_with_size(49153), "valid"
    primary = AssertionError("original worker outcome")
    cause, context = LookupError("original cause"), IndexError("original context")
    try:
        raise primary
    except AssertionError:
        primary.__cause__, primary.__context__, primary.__suppress_context__ = cause, context, False
        original_tb = primary.__traceback__
        assert owner.write_after_cleanup(str(tmp_path / REPORT_NAME), primary=primary) is False
        assert primary.__traceback__ is original_tb
        assert primary.__cause__ is cause and primary.__context__ is context
        assert primary.__suppress_context__ is False
    assert not (tmp_path / REPORT_NAME).exists()


@pytest.mark.parametrize(
    "field,value",
    [("file", "/private/raw"), ("file", "tests/../raw"), ("function", "SELECT secret FROM raw")],
)
def test_bounded_admission_retains_static_label_privacy(field, value):
    report = _literal_report_with_size(49152)
    report["rows"][0][field] = value
    assert profile_module._admit_bounded_report(report) is False


def test_active_bounded_interval_is_unavailable_without_disable_stats_export_or_wait(
    tmp_path, monkeypatch
):
    owner, events = _bounded(monkeypatch)
    entered, release = Event(), Event()
    returned, errors = [], []

    def observe(**kwargs):
        entered.set()
        assert release.wait(1)
        return "original result"

    wrapped = owner.wrap(SimpleNamespace(observe=observe), iteration=2)

    def invoke():
        try:
            returned.append(wrapped.observe(child_pid=17, child_exited=False))
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(1)
        assert owner.availability()["active"] is True
        assert owner.write_after_cleanup(str(tmp_path / REPORT_NAME)) is False
        assert events == ["enable"] and not (tmp_path / REPORT_NAME).exists()
    finally:
        release.set()
        thread.join(1)
    assert not thread.is_alive() and not errors and returned == ["original result"]
    assert events == ["enable", "disable", "getstats", "clear"]


def test_failure_triggered_workflow_inverse_keeps_required_gate_and_exact_two_outputs():
    candidate = Path(__file__).resolve().parents[2]
    text = (candidate / ".github/workflows/ci.yml").read_text()
    first = text.index("  parent-first-observe-profile:\n")
    last = text.index("  backend:\n", first)
    job = text[first:last]
    assert type(WORKFLOW_BASELINE_BYTES) is bytes
    assert len(WORKFLOW_BASELINE_BYTES) == 11070
    assert hashlib.sha256(WORKFLOW_BASELINE_BYTES).hexdigest() == WORKFLOW_BASELINE_SHA256
    original = WORKFLOW_BASELINE_BYTES.decode("utf-8")
    assert text[:first] + text[last:] == original
    assert "needs: [backend-foundations, backend-tests]" in job
    assert (
        "needs.backend-foundations.result == 'success' && needs.backend-tests.result == 'failure'"
        in job
    )
    assert "runs-on: ubuntu-latest" in job and "timeout-minutes: 20" in job
    assert "umask 077\n          mkdir -m 700" in job
    assert job.index("Check architecture") < job.index("Install locked dependencies")
    assert "env -i PATH=" in job and job.count("AQT_PARENT_FIRST_OBSERVE_PROFILE_PATH=") == 1
    assert (
        "tests/integration/test_continuous_simulation_worker.py::test_fixed_worker_runs_real_halted_restore_and_restarts_with_identical_financial_history\n"
        in job
    )
    assert "test_exit=$?" in job and 'exit "$test_exit"' in job
    assert "parent-first-observe-test-exit/1" in job
    uploads = job.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
    assert uploads.splitlines() == [
        "            ${{ runner.temp }}/parent-first-observe-profile/"
        "parent-probe-first-observe.json",
        "            ${{ runner.temp }}/parent-first-observe-profile/test-exit.json",
    ]
    assert job.count("if: ${{ always() }}") == 2 and "retention-days: 7" in job
    assert "if [ ! -f" in job and "exit 1" in job
    aggregate = text[last : text.index("  frontend:", last)]
    assert "needs: [backend-foundations, backend-tests]" in aggregate
    assert "parent-first-observe-profile" not in aggregate


@pytest.mark.parametrize(
    "mutation",
    ["default_factory", "wrong_env", "unguarded_write", "called_bool", "missing_release"],
)
def test_route_golden_rejects_default_or_ownership_mutations_before_execution(mutation):
    tree = ast.parse(current_source())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    block = function.body[1]
    setup = block.body[2]
    if mutation == "default_factory":
        setup.test = ast.Constant(value=True)
    elif mutation == "wrong_env":
        block.body[0].value.args[0] = ast.Constant(value="OTHER_OPT_IN")
    elif mutation == "called_bool":
        setup.body[1].value.keywords[0].value = ast.Call(
            func=ast.Name(id="bool", ctx=ast.Load()), args=[ast.Constant(value=True)], keywords=[]
        )
    elif mutation == "missing_release":
        block.finalbody = [ast.Pass()]
    else:
        handler = next(
            node
            for node in ast.walk(function)
            if isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name)
            and node.type.id == "AssertionError"
        )
        handler.body[2] = handler.body[2].body[0]
    with pytest.raises(AssertionError):
        admitted_function(ast.unparse(ast.fix_missing_locations(tree)).encode())
