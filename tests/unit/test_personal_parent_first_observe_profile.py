"""Finite temporary profile boundaries, not financial or deadline acceptance.

Private native-control replacements below are inert unit seams. They do not add
a public callback API or arbitrary private-global/resource transparency promise.
"""

import ast
import copy
import hashlib
import json
from pathlib import Path
from threading import Event, Thread, get_ident
from types import SimpleNamespace

import pytest

from tests.fixtures import lifecycle_failure_output as failure
from tests.fixtures import lifecycle_forwarding_diagnostic as forwarding
from tests.fixtures import parent_first_observe_profile as profile_module
from tests.fixtures.parent_first_observe_baselines import (
    WORKER_BASELINE_BYTES,
    WORKER_BASELINE_SHA256,
)
from tests.unit.test_personal_worker_parent_diagnostic_wiring import (
    admitted_function,
    current_source,
    without_first_observe_profile,
)


def _projection_leaf():
    return None


def test_genuine_native_entry_projection_has_independent_literal_rows():
    entries = [
        profile_module._NativeEntry(("<built-in method len>", 3, 1, 1.0, 0.5, None)),
        profile_module._NativeEntry(("<built-in method sum>", 2, 0, 2.0, 0.25, None)),
    ]
    report = profile_module._static_report(entries, Path(__file__).resolve().parents[2], False)
    assert report["rows"] == [
        {
            "stats_entry_ordinal": 1,
            "group": "builtin",
            "file": "<builtin>",
            "line": 0,
            "function": "sum",
            "calls": 2,
            "recursive_calls": 0,
            "inclusive_seconds": 2.0,
            "self_seconds": 0.25,
        },
        {
            "stats_entry_ordinal": 0,
            "group": "builtin",
            "file": "<builtin>",
            "line": 0,
            "function": "len",
            "calls": 3,
            "recursive_calls": 1,
            "inclusive_seconds": 1.0,
            "self_seconds": 0.5,
        },
    ]
    assert report["observe_returned"] is False and report["stats_entries_considered"] == 2


def test_selection_reaches_exact_512_row_cap_without_exporting_raw_entries():
    native = profile_module._NativeEntry
    entries = []
    for code, total, own in (
        ("<built-in method len>", 40.0, 0.2),
        ("<built-in method sum>", 30.0, 5.0),
        (_projection_leaf.__code__, 20.0, 0.1),
        (_projection_leaf.__code__, 10.0, 4.0),
        ("<built-in method len>", 1.0, 0.0),
    ):
        entries.extend(native((code, 1, 0, total, own, None)) for _ in range(128))
    report = profile_module._static_report(entries, Path(__file__).resolve().parents[2], True)
    assert report["stats_entries_considered"] == 640
    assert len(report["rows"]) == 512
    assert {row["stats_entry_ordinal"] for row in report["rows"]} == set(range(512))
    assert [row["inclusive_seconds"] for row in report["rows"]] == [
        *([40.0] * 128),
        *([30.0] * 128),
        *([20.0] * 128),
        *([10.0] * 128),
    ]
    assert len((json.dumps(report, indent=2, allow_nan=False) + "\n").encode()) < 1_000_000
    assert all(type(value) in (str, int, float) for row in report["rows"] for value in row.values())


def test_unknown_code_with_custom_metaclass_equality_is_rejected_without_hooks():
    class ForeignMeta(type):
        def __eq__(cls, other):
            pytest.fail("foreign class equality was called")

    class ForeignCode(metaclass=ForeignMeta):
        pass

    entry = profile_module._NativeEntry((ForeignCode(), 1, 0, 1.0, 0.5, None))
    with pytest.raises(ValueError, match="PARENT_PROFILE_NATIVE_STATS"):
        profile_module._static_report([entry], Path(__file__).resolve().parents[2], True)


def test_disable_and_scalar_conversion_stay_in_probe_thread_while_active_writer_is_unknown(
    tmp_path,
):
    entered, released = Event(), Event()
    events, results, faults = [], [], []

    class NativeStub:
        def enable(self):
            events.append(("enable", get_ident()))

        def disable(self):
            events.append(("disable", get_ident()))

        def getstats(self):
            events.append(("getstats", get_ident()))
            return []

        def clear(self):
            events.append(("clear", get_ident()))

    profile = profile_module.create_first_observe_profile(enabled=True)
    profile._factory, profile._profile_type = NativeStub, NativeStub
    profile._getprofile = profile._gettrace = lambda: None
    profile._get_tool = lambda tool: None
    profile._get_events = lambda tool: 0
    token = object()

    def operation(**kwargs):
        assert kwargs == {"child_pid": 17, "child_exited": False}
        entered.set()
        assert released.wait(1)
        return token

    wrapped = profile.wrap(SimpleNamespace(observe=operation), iteration=2)

    def invoke():
        try:
            results.append(wrapped.observe(child_pid=17, child_exited=False))
        except BaseException as error:
            faults.append(error)

    thread = Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(1)
        assert profile.availability()["active"] is True
        assert (
            profile.write_after_cleanup(str(tmp_path / "parent-probe-first-observe.json")) is False
        )
        assert [row[0] for row in events] == ["enable"]
    finally:
        released.set()
        thread.join(1)
    assert not thread.is_alive() and not faults and results == [token]
    assert [row[0] for row in events] == ["enable", "disable", "getstats", "clear"]
    assert len({row[1] for row in events}) == 1 and events[0][1] != get_ident()
    assert profile._profiler is profile._disable is profile._getstats is profile._clear is None


@pytest.fixture
def inert_profile(monkeypatch):
    events = []

    class NativeFixtureProfile:
        def __init__(self):
            events.append("construct")

        def enable(self):
            events.append("enable")

        def disable(self):
            events.append("disable")

        def getstats(self):
            events.append("getstats")
            return []

        def clear(self):
            events.append("clear")

    monkeypatch.setattr(profile_module, "_NativeProfile", NativeFixtureProfile)
    monkeypatch.setattr(profile_module, "_native_getprofile", lambda: None)
    monkeypatch.setattr(profile_module, "_native_gettrace", lambda: None)
    monkeypatch.setattr(profile_module, "_native_get_tool", lambda tool: None)
    monkeypatch.setattr(profile_module, "_native_get_events", lambda tool: 0)
    return profile_module.create_first_observe_profile(enabled=True), events


@pytest.mark.parametrize("value", [None, 0, 1, "yes", [], object(), lambda: True])
def test_nonexact_optin_rejected_before_helper_or_native_owners(monkeypatch, value):
    def forbidden(*args, **kwargs):
        pytest.fail("no construction or owner hook may run")

    monkeypatch.setattr(profile_module, "FirstObserveProfile", forbidden)
    with pytest.raises(TypeError, match="PARENT_PROFILE_EXACT_BOOL"):
        profile_module.create_first_observe_profile(enabled=value)


def test_default_false_returns_original_without_new_helper_frames_or_hooks(monkeypatch):
    delegate = SimpleNamespace(observe=lambda **kwargs: kwargs, prepare=lambda value: value)

    def forbidden(*args, **kwargs):
        pytest.fail("default path constructed new diagnostic")

    monkeypatch.setattr(profile_module, "FirstObserveProfile", forbidden)
    assert profile_module.create_first_observe_profile() is None
    assert profile_module.create_first_observe_profile(enabled=False) is None
    assert (
        profile_module.wrap_first_observe_profile(delegate, profile=None, iteration=2) is delegate
    )
    assert delegate.observe(child_pid=123, child_exited=False) == {
        "child_pid": 123,
        "child_exited": False,
    }


@pytest.mark.parametrize("timed", [False, True])
def test_default_keeps_literal_existing_v1_v2_failure_bytes(monkeypatch, timed):
    manager = failure.create_parent_diagnostics(native_timing=timed)
    lines = []
    monkeypatch.setattr(failure.sys, "stdout", SimpleNamespace(write=lines.append))
    failure.emit_parent_failure_line(manager, iteration=2)
    original = lines.pop()
    assert profile_module.create_first_observe_profile(enabled=False) is None
    failure.emit_parent_failure_line(manager, iteration=2)
    assert lines == [original]
    payload = json.loads(original[len(failure.PREFIX) :])
    assert payload["schema_version"] == (2 if timed else 1)
    assert len(original) <= 4096 and original.isascii()


def test_only_iteration_two_first_observe_is_profiled_and_other_ports_forward(inert_profile):
    profile, events = inert_profile
    result = object()

    class Delegate:
        def prepare(self, startup):
            events.append(("prepare", startup))
            return startup

        def require_result(self, payload):
            events.append(("result", payload))
            return payload

        def observe(self, *, child_pid, child_exited):
            events.append(("observe", child_pid, child_exited))
            return result

    delegate = Delegate()
    assert profile.wrap(delegate, iteration=1) is delegate
    assert events == []
    wrapped = profile.wrap(delegate, iteration=2)
    token = object()
    assert wrapped.prepare(token) is token and wrapped.require_result(token) is token
    assert events == [("prepare", token), ("result", token)]
    assert wrapped.observe(child_pid=71, child_exited=False) is result
    assert wrapped.observe(child_pid=72, child_exited=True) is result
    assert events[2:] == [
        "construct",
        "enable",
        ("observe", 71, False),
        "disable",
        "getstats",
        "clear",
        ("observe", 72, True),
    ]
    assert profile.availability() == {
        "schema_version": 1,
        "selected": True,
        "active": False,
        "completed": True,
        "available": True,
        "report_written": False,
    }


def test_first_actual_call_contention_is_consumed_without_profiling_later(inert_profile):
    profile, events = inert_profile
    calls = []
    delegate = SimpleNamespace(observe=lambda **kwargs: calls.append(kwargs))
    wrapped = profile.wrap(delegate, iteration=2)
    assert profile._lock.acquire(blocking=False)
    try:
        wrapped.observe(child_pid=31, child_exited=False)
    finally:
        profile._lock.release()
    wrapped.observe(child_pid=32, child_exited=False)
    assert len(calls) == 2 and events == []
    assert profile.availability()["available"] is False
    assert profile.availability()["completed"] is True


def test_original_fresh_sql_lookup_stays_after_start_clocks_inside_profile(
    inert_profile, monkeypatch
):
    profile, events = inert_profile
    values = iter((10, 20))
    monkeypatch.setattr(
        forwarding, "_native_wall_time_ns", lambda: events.append("wall") or next(values)
    )
    monkeypatch.setattr(forwarding, "_native_thread_time_ns", lambda: events.append("cpu") or 5)

    class Delegate:
        @property
        def observe(self):
            events.append("fresh-SQL-lookup")
            return lambda **kwargs: events.append(("callback", kwargs)) or "returned"

    diagnostic = forwarding.LifecycleForwardingDiagnostic(native_timing=True)
    observed = forwarding.ObservedLifecycle(Delegate(), diagnostic)
    wrapped = profile.wrap(observed, iteration=2)
    assert wrapped.observe(child_pid=41, child_exited=False) == "returned"
    assert events == [
        "construct",
        "enable",
        "wall",
        "cpu",
        "fresh-SQL-lookup",
        ("callback", {"child_pid": 41, "child_exited": False}),
        "wall",
        "cpu",
        "disable",
        "getstats",
        "clear",
    ]
    assert diagnostic.snapshot()["stages"]["observe"] == {
        "entered": 1,
        "returned": 1,
        "raised": 0,
        "active": 0,
    }


def test_delegate_alias_and_method_rebinding_cannot_replace_stored_native_controls(
    inert_profile, monkeypatch
):
    profile, events = inert_profile

    def forbidden(*args, **kwargs):
        pytest.fail("rebound control was called")

    def operation(**kwargs):
        monkeypatch.setattr(profile_module, "_native_getprofile", forbidden)
        monkeypatch.setattr(profile_module, "_native_gettrace", forbidden)
        monkeypatch.setattr(profile_module, "_NativeProfile", forbidden)
        profile._profiler.disable = forbidden
        profile._profiler.getstats = forbidden
        profile._profiler.clear = forbidden
        return 51

    assert (
        profile.wrap(SimpleNamespace(observe=operation), iteration=2).observe(
            child_pid=51, child_exited=False
        )
        == 51
    )
    assert events == ["construct", "enable", "disable", "getstats", "clear"]


@pytest.mark.parametrize("owner", ["profile", "trace", "monitoring-name", "monitoring-events"])
def test_existing_hook_owner_blocks_activation_without_replacement(inert_profile, owner):
    profile, events = inert_profile
    token = object()
    if owner == "profile":
        profile._getprofile = lambda: token
    elif owner == "trace":
        profile._gettrace = lambda: token
    elif owner == "monitoring-name":
        profile._get_tool = lambda tool: "existing" if tool == 2 else None
    else:
        profile._get_events = lambda tool: 1 if tool == 3 else 0
    calls = []
    wrapped = profile.wrap(
        SimpleNamespace(observe=lambda **kwargs: calls.append(kwargs)), iteration=2
    )
    wrapped.observe(child_pid=11, child_exited=False)
    wrapped.observe(child_pid=12, child_exited=False)
    assert len(calls) == 2 and events == []
    assert profile.availability()["available"] is False


def test_detected_unsupported_takeover_denies_direct_disable_and_export(inert_profile, tmp_path):
    profile, events = inert_profile
    foreign = object()

    def operation(**kwargs):
        profile._getprofile = lambda: foreign
        return 5

    assert (
        profile.wrap(SimpleNamespace(observe=operation), iteration=2).observe(
            child_pid=5, child_exited=False
        )
        == 5
    )
    assert events == ["construct", "enable"]
    assert profile.availability()["available"] is False
    assert profile.write_after_cleanup(str(tmp_path / "parent-probe-first-observe.json")) is False
    # This inert control proves only direct-call avoidance. It does not prove
    # native destruction preserves a foreign hook after unsupported takeover.


def test_stopped_scalar_report_exclusive_file_and_bounded_companion_line(
    inert_profile, tmp_path, monkeypatch
):
    profile, events = inert_profile
    wrapped = profile.wrap(SimpleNamespace(observe=lambda **kwargs: 7), iteration=2)
    assert wrapped.observe(child_pid=7, child_exited=False) == 7
    tmp_path.chmod(0o700)
    output = tmp_path / "parent-probe-first-observe.json"
    assert profile.write_after_cleanup(str(output)) is True
    raw = output.read_bytes()
    data = json.loads(raw)
    assert data["schema"] == "parent-probe-iteration2-first-observe-static-cprofile/1"
    assert data["iteration"] == 2 and data["observe_ordinal"] == 1
    assert data["observe_started"] is True and data["observe_returned"] is True
    assert data["stats_entries_considered"] == 0 and data["rows"] == []
    assert raw == (json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    assert len(raw) <= 1_000_000 and output.stat().st_mode & 0o777 == 0o600
    assert profile.write_after_cleanup(str(output)) is False
    assert output.read_bytes() == raw and events.count("getstats") == 1
    lines = []
    monkeypatch.setattr(profile_module.sys, "stdout", SimpleNamespace(write=lines.append))
    profile.emit_availability()
    assert lines == [
        'AQT_PARENT_FIRST_OBSERVE_PROFILE {"schema_version":1,"selected":true,'
        '"active":false,"completed":true,"available":true,"report_written":true}\n'
    ]
    assert len(lines[0]) <= 4096 and lines[0].isascii()
    assert "rows" not in lines[0] and str(tmp_path) not in lines[0]


def test_worker_profile_delta_inverts_to_preceding_exact_ast_and_eight_assertions():
    assert type(WORKER_BASELINE_BYTES) is bytes
    assert len(WORKER_BASELINE_BYTES) == 3799
    assert hashlib.sha256(WORKER_BASELINE_BYTES).hexdigest() == WORKER_BASELINE_SHA256
    tree, executable = without_first_observe_profile(ast.parse(current_source()))
    assert ast.dump(tree, include_attributes=False) == ast.dump(
        ast.parse(WORKER_BASELINE_BYTES), include_attributes=False
    )
    assert sum(isinstance(node, ast.Assert) for node in ast.walk(executable)) == 8
    assert admitted_function(current_source())


@pytest.mark.parametrize(
    "mutation",
    ["false", "called", "wrong_iteration", "hoisted", "path", "no_primary", "print_first"],
)
def test_worker_gate_rejects_profile_wiring_mutations_without_execution(mutation):
    tree = ast.parse(current_source())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    factory = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "create_bounded_first_observe_profile"
    )
    wrapper = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "wrap_first_observe_profile"
    )
    handler = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.ExceptHandler)
        and isinstance(n.type, ast.Name)
        and n.type.id == "AssertionError"
    )
    if mutation == "false":
        factory.keywords[0].value = ast.Constant(value=False)
    elif mutation == "called":
        factory.keywords[0].value = ast.Call(
            func=ast.Name(id="foreign", ctx=ast.Load()), args=[], keywords=[]
        )
    elif mutation == "wrong_iteration":
        wrapper.keywords[1].value = ast.Constant(value=1)
    elif mutation == "hoisted":
        wrapper.args[0] = ast.Name(id="hoisted_delegate", ctx=ast.Load())
    elif mutation == "path":
        write = handler.body[2].body[0].value
        write.args[0] = ast.Constant(value="other.json")
    elif mutation == "no_primary":
        handler.body[2].body[0].value.keywords.clear()
    else:
        handler.body.insert(0, copy.deepcopy(handler.body[2]))
    with pytest.raises(AssertionError):
        admitted_function(ast.unparse(ast.fix_missing_locations(tree)).encode("utf-8"))
