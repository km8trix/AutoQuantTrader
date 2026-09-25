"""Check bounded diagnostic output without running retained history or profilers."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import retained_restore_profile as profile


def _entry(code, *, calls=1, inclusive=1.0, exclusive=0.5):
    return SimpleNamespace(
        code=code,
        callcount=calls,
        reccallcount=0,
        totaltime=inclusive,
        inlinetime=exclusive,
    )


class FakeProfiler:
    def __init__(self, entries):
        self.entries = entries
        self.disabled = False

    def disable(self):
        self.disabled = True

    def getstats(self):
        assert self.disabled
        return self.entries


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<built-in method builtins.len>", "builtins.len"),
        ("<built-in method now of type object at 0xABC123>", "now"),
        ("<method 'append' of 'list' objects>", "list.append"),
        ("<function private_callback at 0xABC123>", "<builtin>"),
        ("unknown description PRIVATE_PROVIDER_VALUE", "<builtin>"),
    ],
)
def test_builtin_label_is_allowlisted_and_never_emits_addresses_or_unknown_values(raw, expected):
    assert profile._builtin_label(raw) == expected


def test_static_code_labels_omit_machine_roots_and_distinguish_project_from_dependencies():
    project = Path("/checkout")
    code = _entry.__code__
    observed = [
        profile._static_location(code.replace(co_filename=filename), project)
        for filename in (
            "/checkout/packages/domain/canonical.py",
            "/checkout/.venv/lib/python3.12/site-packages/sqlalchemy/sql/elements.py",
            "/opt/python/lib/python3.12/json/encoder.py",
            "<dynamic PRIVATE_VALUE>",
        )
    ]
    assert [(row[0], row[1]) for row in observed] == [
        ("project", "packages/domain/canonical.py"),
        ("dependency", "sqlalchemy/sql/elements.py"),
        ("runtime", "encoder.py"),
        ("generated", "<generated>"),
    ]
    assert "PRIVATE_VALUE" not in json.dumps(observed)


def test_large_stats_keep_bounded_top_union_and_distinct_ordinals_without_raw_dump():
    entries = [
        _entry(
            "<method 'append' of 'list' objects>", inclusive=float(i), exclusive=float(11000 - i)
        )
        for i in range(11000)
    ]
    profiler = FakeProfiler(entries)
    profiler.disable()
    report = profile._report(
        profiler, Path("/checkout"), execute_started=True, execute_returned=False
    )
    assert report["stats_entries_considered"] == 11000
    assert report["factory_execute_returned"] is False
    assert len(report["rows"]) == 256 <= 512
    ordinals = {row["stats_entry_ordinal"] for row in report["rows"]}
    assert ordinals == set(range(128)) | set(range(11000 - 128, 11000))
    assert len({(row["file"], row["line"], row["function"]) for row in report["rows"]}) == 1
    assert "Inclusive times overlap" in report["selection"]
    assert "not cProfile internal storage" in report["selection"]


def test_written_report_is_private_sanitized_and_does_not_claim_test_success(tmp_path):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FakeProfiler([_entry("<built-in method now of type object at 0xABC123>")])
    capture.execute_started = True
    capture.write_report()
    raw = capture.output.read_bytes()
    report = json.loads(raw)
    assert capture.profiler.disabled and capture.report_written and capture.profile_valid
    assert capture.output.stat().st_mode & 0o777 == 0o600
    assert b"0xABC123" not in raw
    assert len(raw) <= 1_000_000
    assert report["diagnostic_only"] is True
    assert report["factory_execute_started"] is True
    assert report["factory_execute_returned"] is False
    assert "passing restore test" in report["scope"]
    assert set(report["rows"][0]) == {
        "stats_entry_ordinal",
        "group",
        "file",
        "line",
        "function",
        "calls",
        "recursive_calls",
        "inclusive_seconds",
        "self_seconds",
    }


def test_reporting_failure_is_sanitized_and_cannot_replace_an_original_exception(tmp_path, capsys):
    class BrokenProfiler:
        def disable(self):
            raise ValueError("PRIVATE_DIAGNOSTIC_VALUE")

    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = BrokenProfiler()
    original = RuntimeError("original failure")
    with pytest.raises(RuntimeError) as raised:
        try:
            raise original
        finally:
            capture.write_report()
    assert raised.value is original
    assert capture.report_written and not capture.profile_valid
    report = json.loads(capture.output.read_bytes())
    assert report["profile_status"] == "invalid" and report["rows"] == []
    assert report["diagnostic_faults"] == ["report_disable_failed"]
    assert "PRIVATE_DIAGNOSTIC_VALUE" not in capture.output.read_text()
    assert capsys.readouterr().out == ""


def test_exclusive_report_creation_preserves_existing_evidence(tmp_path):
    path = tmp_path / "profile.json"
    path.write_bytes(b"original evidence")
    capture = profile.RetainedRestoreProfile(str(path))
    capture.profiler = FakeProfiler([])
    capture.write_report()
    assert not capture.report_written
    assert path.read_bytes() == b"original evidence"


def test_byte_bound_rejects_before_opening_an_output(tmp_path, monkeypatch):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FakeProfiler([])
    monkeypatch.setattr(profile, "_MAX_REPORT_BYTES", 1)
    capture.write_report()
    assert not capture.report_written and not capture.output.exists()


def test_nonfinite_time_cannot_be_serialized_into_report(tmp_path):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FakeProfiler(
        [_entry("<built-in method builtins.len>", inclusive=float("nan"))]
    )
    capture.write_report()
    assert not capture.report_written and not capture.output.exists()


class FaultProfiler(FakeProfiler):
    def __init__(self, *, enable_error=None, disable_error=None):
        super().__init__([])
        self.enable_error = enable_error
        self.disable_error = disable_error
        self.calls = []

    def enable(self):
        self.calls.append("enable")
        if self.enable_error is not None:
            raise self.enable_error

    def disable(self):
        self.calls.append("disable")
        if self.disable_error is not None:
            raise self.disable_error
        super().disable()


@pytest.mark.parametrize("original_kind", [RuntimeError, KeyboardInterrupt])
def test_actual_optional_execute_wrapper_preserves_original_error_when_disable_also_fails(
    tmp_path, original_kind
):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FaultProfiler(disable_error=RuntimeError("private disable detail"))
    original = original_kind("original execute error")
    calls = []

    def execute(*, operation_id):
        calls.append(operation_id)
        raise original

    with pytest.raises(original_kind) as raised:
        capture.execute(execute, operation_id="fixed-operation")
    assert raised.value is original
    assert calls == ["fixed-operation"]
    assert capture.execute_started and not capture.execute_returned
    capture.write_report()
    report = json.loads(capture.output.read_bytes())
    assert capture.report_written and not capture.profile_valid
    assert report["profile_status"] == "invalid" and report["rows"] == []
    assert report["diagnostic_faults"] == ["execute_disable_failed", "report_disable_failed"]
    assert "private disable detail" not in capture.output.read_text()


def test_actual_optional_execute_wrapper_preserves_enable_error_and_unstarted_flags(tmp_path):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    original = RuntimeError("original enable error")
    capture.profiler = FaultProfiler(enable_error=original)
    calls = []
    with pytest.raises(RuntimeError) as raised:
        capture.execute(lambda: calls.append("unexpected"))
    assert raised.value is original and calls == []
    assert not capture.execute_started and not capture.execute_returned
    capture.write_report()
    assert capture.report_written and not capture.profile_valid
    report = json.loads(capture.output.read_bytes())
    assert report["diagnostic_faults"] == ["enable_failed"] and report["rows"] == []


def test_successful_execute_with_failed_disable_returns_value_but_invalidates_profile(tmp_path):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FaultProfiler(disable_error=RuntimeError("disable error"))
    value = object()
    assert capture.execute(lambda: value) is value
    assert capture.execute_started and capture.execute_returned
    capture.write_report()
    assert capture.report_written and not capture.profile_valid
    assert json.loads(capture.output.read_bytes())["rows"] == []


@pytest.mark.parametrize("original_kind", [AssertionError, RuntimeError])
def test_write_failure_and_broken_stdout_cannot_replace_original_assertion_or_cleanup_error(
    tmp_path, monkeypatch, original_kind
):
    path = tmp_path / "profile.json"
    path.write_bytes(b"prior evidence")
    capture = profile.RetainedRestoreProfile(str(path))
    capture.profiler = FakeProfiler([])

    def broken_print(*args, **kwargs):
        raise BrokenPipeError("private stdout detail")

    monkeypatch.setattr("builtins.print", broken_print)
    original = original_kind("original assertion or cleanup error")
    with pytest.raises(original_kind) as raised:
        try:
            raise original
        finally:
            capture.write_report()
    assert raised.value is original
    assert not capture.report_written and not capture.profile_valid
    assert capture.diagnostic_faults == ["report_write_failed"]
    assert path.read_bytes() == b"prior evidence"


def test_broken_stdout_does_not_prevent_valid_report_because_reporter_is_silent(
    tmp_path, monkeypatch
):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    capture.profiler = FakeProfiler([])

    def broken_print(*args, **kwargs):
        raise BrokenPipeError("private stdout detail")

    monkeypatch.setattr("builtins.print", broken_print)
    capture.write_report()
    assert capture.report_written and capture.profile_valid
    assert json.loads(capture.output.read_bytes())["profile_status"] == "valid"


@pytest.mark.parametrize(
    "scenario",
    [
        "execute-and-disable",
        "enable",
        "success-disable",
        "assertion-report-write",
        "cleanup-report-write",
        "execute-cleanup-report-write",
        "default-disabled",
    ],
)
def test_actual_integration_wrapper_keeps_original_failures_and_cleanup_with_finite_fakes(
    tmp_path, monkeypatch, scenario
):
    from contextlib import nullcontext

    from apps.trader.continuous_simulation_factory import _ActualClock
    from tests.integration import test_continuous_simulation_factory_outcome as integration

    execute_error = RuntimeError("original execute failure")
    cleanup_error = RuntimeError("original cleanup failure")
    enable_error = RuntimeError("original enable failure")
    calls = []
    independent = ("independent synthetic sentinel",)
    venue = SimpleNamespace(read=lambda: independent)
    pair = SimpleNamespace(
        base=SimpleNamespace(
            h=SimpleNamespace(
                lease=SimpleNamespace(fence="old-fence"),
                coordinator=SimpleNamespace(release=lambda fence: calls.append(("release", fence))),
            ),
            scope=SimpleNamespace(account_id="synthetic-account"),
        ),
        counts=lambda: (1, 2, 3),
        venue=venue,
    )
    original = SimpleNamespace(
        checkpoint=SimpleNamespace(semantic_sha256="checkpoint"),
        receipt=SimpleNamespace(commit=SimpleNamespace(semantic_sha256="commit")),
    )
    daily = SimpleNamespace(assignment=SimpleNamespace(semantic_sha256="assignment"))
    history = (pair, None, original, daily, object(), independent, ())
    output = tmp_path / "profile.json"
    if "report-write" in scenario:
        output.write_bytes(b"prior diagnostic evidence")
    capture = profile.RetainedRestoreProfile(str(output))
    capture.profiler = FaultProfiler(
        enable_error=enable_error if scenario == "enable" else None,
        disable_error=RuntimeError("disable failure") if "disable" in scenario else None,
    )

    class Factory:
        def __init__(self, config, *, account_id, stop_requested):
            self.clock = _ActualClock()
            self.lease = SimpleNamespace(fence="new-fence")
            self.outcomes = SimpleNamespace(require_bindings=lambda: None)
            self.delivery = SimpleNamespace(
                publisher=SimpleNamespace(require_completed=self.reject)
            )
            self.venue = venue
            self.engine = object()
            self.venue_engine = object()
            calls.append(("factory", account_id))

        def reject(self, batch):
            raise ValueError("SUCCESSFUL_DISPATCH_COMMIT")

        def execute(self, *, operation_id):
            calls.append(("execute", operation_id))
            if scenario in {"execute-and-disable", "execute-cleanup-report-write"}:
                raise execute_error
            return json.dumps(
                {
                    "checkpoint_sha256": (
                        "wrong" if scenario == "assertion-report-write" else "checkpoint"
                    ),
                    "commit_sha256": "commit",
                    "assignment_sha256": "assignment",
                    "status": "restored",
                }
            )

        def close(self):
            calls.append(("close",))
            self.engine = self.venue_engine = None
            if scenario in {"cleanup-report-write", "execute-cleanup-report-write"}:
                raise cleanup_error

    monkeypatch.setattr(integration, "ContinuousSimulationFactory", Factory)
    monkeypatch.setattr(integration, "_no_new_sources", lambda _patch: nullcontext())
    if scenario == "default-disabled":
        monkeypatch.delenv("AQT_RETAINED_RESTORE_PROFILE_PATH", raising=False)

        def forbidden_profile(_output):
            raise AssertionError("disabled path constructed a profiler")

        monkeypatch.setattr(profile, "RetainedRestoreProfile", forbidden_profile)
        integration._execute_retained_factory(history, None, monkeypatch)
        assert not output.exists()
    else:
        monkeypatch.setenv("AQT_RETAINED_RESTORE_PROFILE_PATH", str(output))
        monkeypatch.setattr(profile, "RetainedRestoreProfile", lambda _output: capture)
        if scenario == "execute-cleanup-report-write":
            expected = ExceptionGroup
        elif scenario in {"success-disable", "assertion-report-write"}:
            expected = AssertionError
        else:
            expected = RuntimeError
        with pytest.raises(expected) as raised:
            integration._execute_retained_factory(history, None, monkeypatch)
        if scenario == "execute-and-disable":
            assert raised.value is execute_error
        elif scenario == "enable":
            assert raised.value is enable_error
            assert not capture.execute_started and not capture.execute_returned
            assert not any(call[0] == "execute" for call in calls)
        elif scenario == "cleanup-report-write":
            assert raised.value is cleanup_error
        elif scenario == "execute-cleanup-report-write":
            assert raised.value.exceptions == (execute_error, cleanup_error)
        elif scenario == "success-disable":
            assert str(raised.value).startswith("RETAINED_PROFILE_REPORT_FAILED")
        else:
            assert "checkpoint" in str(raised.value)
        assert not capture.profile_valid
        if "report-write" in scenario:
            assert output.read_bytes() == b"prior diagnostic evidence"
    assert calls[0] == ("release", "old-fence")
    assert calls[-1] == ("close",)
