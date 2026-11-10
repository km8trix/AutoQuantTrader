"""Fake-only assay boundaries; no OS signal, child, timer or CLI teardown proof.

The helper is loaded only when a test runs. Process and timer operations are
trapped during loading, then replaced with strict module-local fakes. Only local
pipes and tmp_path file persistence use the real OS. These tests do not qualify
real process ownership, Popen internals, deadlines, CPU/RAM or restore behavior.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "docs/tools/owned_child_signal_assay.py"
FAKE_PID = 2_000_000_001


def _forbidden(*_args, **_kwargs):
    raise AssertionError("real process, signal, timer or CLI teardown is forbidden")


class _Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        self.now += 0.001
        return self.now


class _NoWaitSelector:
    """Read only the fixture's local pipe FDs; never wait for real elapsed time."""

    def __init__(self):
        self.inner = selectors.DefaultSelector()

    def register(self, *args):
        return self.inner.register(*args)

    def unregister(self, *args):
        return self.inner.unregister(*args)

    def get_map(self):
        return self.inner.get_map()

    def select(self, _timeout):
        return self.inner.select(0)

    def close(self):
        self.inner.close()


class _Signals:
    SIGALRM = signal.SIGALRM
    SIGKILL = signal.SIGKILL
    SIG_DFL = signal.SIG_DFL
    SIG_UNBLOCK = signal.SIG_UNBLOCK
    ITIMER_REAL = signal.ITIMER_REAL

    def __init__(self):
        self.calls = []

    def signal(self, number, handler):
        assert (number, handler) == (self.SIGALRM, self.SIG_DFL)
        self.calls.append(("default", number, handler))

    def pthread_sigmask(self, how, numbers):
        assert how == self.SIG_UNBLOCK and numbers == {self.SIGALRM}
        self.calls.append(("unblock", how, numbers.copy()))
        return set()

    def setitimer(self, kind, seconds, interval=0):
        assert (kind, seconds, interval) == (self.ITIMER_REAL, 60.0, 0)
        self.calls.append(("timer", kind, seconds))
        return (0.0, 0.0)


class _ProcessOS:
    """Delegate file operations, but never delegate process-control operations."""

    def __init__(self, rig):
        self.rig = rig
        self.environ = dict(rig.module.ENVIRONMENT)

    def __getattr__(self, name):
        if name in {
            "kill",
            "fork",
            "forkpty",
            "posix_spawn",
            "posix_spawnp",
            "system",
            "popen",
            "wait",
            "waitpid",
            "waitid",
            "_exit",
            "abort",
        } or name.startswith(("exec", "spawn")):
            return _forbidden
        return getattr(os, name)

    def getpgid(self, pid):
        assert pid == FAKE_PID
        return FAKE_PID + 1 if self.rig.foreign_query == "pgid" else FAKE_PID

    def getsid(self, pid):
        if pid == 0:
            return os.getsid(0)
        assert pid == FAKE_PID
        return FAKE_PID + 1 if self.rig.foreign_query == "sid" else FAKE_PID

    def killpg(self, pid, number):
        assert pid == FAKE_PID and self.rig.child is not None
        child = self.rig.child
        if number == signal.SIGKILL:
            assert not self.rig.waits and child.returncode is None
            assert not any(action == "KILL" for action in self.rig.actions)
            self.rig.actions.append("KILL")
            if self.rig.deny_kill:
                raise PermissionError(errno.EPERM, "fake KILL denied")
            child.killed = True
            return None
        assert number == 0 and len(self.rig.waits) == 1 and child.returncode is not None
        assert "PROBE" not in self.rig.actions
        self.rig.actions.append("PROBE")
        if self.rig.group_probe == "denied":
            raise PermissionError(errno.EPERM, "fake group probe denied")
        if self.rig.group_probe == "present":
            return None
        raise ProcessLookupError(errno.ESRCH, "fake owned group absent")


class _Child:
    def __init__(self, rig, command):
        self.rig = rig
        self.args = command
        self.pid = FAKE_PID
        self.returncode = None
        self.killed = False
        stdout_r, stdout_w = os.pipe()
        stderr_r, stderr_w = os.pipe()
        self.stdout = os.fdopen(stdout_r, "rb", buffering=0)
        self.stderr = os.fdopen(stderr_r, "rb", buffering=0)
        self.writers = {"stdout": stdout_w, "stderr": stderr_w}
        self.ready = rig.readiness()
        assert len(self.ready) <= 256
        if self.ready:
            assert os.write(stdout_w, self.ready) == len(self.ready)
        if rig.readiness_stderr:
            assert os.write(stderr_w, rig.readiness_stderr) == len(rig.readiness_stderr)
        if rig.ready_kind == "empty":
            self.close_writers()

    def close_writer(self, name):
        fd = self.writers.pop(name, None)
        if fd is not None:
            os.close(fd)

    def close_writers(self):
        for name in tuple(self.writers):
            self.close_writer(name)

    def wait(self, *, timeout):
        assert not self.rig.waits and self.returncode is None
        assert 0 <= timeout <= self.rig.module.TOTAL_SECONDS
        self.rig.waits.append(timeout)
        self.rig.actions.append("WAIT")
        if self.rig.tail:
            fd = self.writers["stdout"]
            assert os.write(fd, self.rig.tail) == len(self.rig.tail)
        self.close_writer("stdout")
        if not self.rig.missing_stderr_eof:
            self.close_writer("stderr")
        if self.rig.wait_timeout:
            raise subprocess.TimeoutExpired(self.args, timeout)
        self.returncode = -signal.SIGKILL if self.killed else -signal.SIGALRM
        return self.returncode

    poll = communicate = kill = terminate = __enter__ = __exit__ = _forbidden


class _Rig:
    def __init__(self, directory):
        self.directory = directory.resolve()
        self.root = self.directory / "fresh-assay"
        self.module = None
        self.child = None
        self.launches = []
        self.actions = []
        self.waits = []
        self.root_fds = []
        self.summaries = []
        self.reports = []
        self.ready_kind = "valid"
        self.constructor_error = None
        self.readiness_stderr = b""
        self.foreign_query = None
        self.deny_kill = False
        self.wait_timeout = False
        self.group_probe = "absent"
        self.tail = b""
        self.missing_stderr_eof = False
        self.signals = _Signals()

    def readiness(self):
        row = {
            "pid": FAKE_PID,
            "ppid": os.getpid(),
            "uid": os.getuid(),
            "pgid": FAKE_PID,
            "sid": FAKE_PID,
        }
        if self.ready_kind == "empty":
            return b""
        if self.ready_kind == "malformed":
            return b"not-json\n"
        if self.ready_kind == "foreign_parent":
            row["ppid"] += 1
        elif self.ready_kind == "foreign_pid":
            row["pid"] += 1
        elif self.ready_kind == "bool_pid":
            row["pid"] = True
        elif self.ready_kind == "wrong_order":
            row = dict(reversed(tuple(row.items())))
        return (json.dumps(row, separators=(",", ":")) + "\n").encode("ascii")

    def popen(self, command, **options):
        assert self.child is None and not self.launches
        assert command == [sys.executable, "-I", "-S", "-B", "-c", self.module.CHILD_SOURCE]
        assert options == {
            "cwd": str(self.root),
            "env": self.module.ENVIRONMENT,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "close_fds": True,
            "start_new_session": True,
        }
        assert stat.S_IMODE(self.root.stat().st_mode) == 0o700
        assert not tuple(self.root.iterdir())
        self.launches.append((command, options))
        if self.constructor_error is not None:
            raise self.constructor_error
        self.child = _Child(self, command)
        return self.child

    def run(self, monkeypatch, *, execute=True):
        argv = [str(SOURCE)]
        if execute:
            argv += ["--execute", "--output-root", str(self.root)]
        monkeypatch.setattr(sys, "argv", argv)
        self.module.sys.argv = argv
        return self.module.main()

    def report(self):
        return json.loads((self.root / "report.json").read_bytes())

    def close(self):
        if self.child is not None:
            self.child.close_writers()
            self.child.stdout.close()
            self.child.stderr.close()
        if self.root.exists():
            self.root.chmod(0o700)
            report = self.root / "report.json"
            if report.exists():
                report.chmod(0o600)


@pytest.fixture
def rig(tmp_path, monkeypatch):
    value = _Rig(tmp_path)
    spec = importlib.util.spec_from_file_location("_aqt_owned_child_assay_fake_only", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Future import-time process/timer additions must fail before local proxies exist.
    with monkeypatch.context() as loading:
        loading.setattr(subprocess, "Popen", _forbidden)
        process_names = {
            "kill",
            "killpg",
            "fork",
            "forkpty",
            "posix_spawn",
            "posix_spawnp",
            "_exit",
            "system",
            "popen",
            "wait",
            "waitpid",
            "waitid",
            "abort",
        }
        for name in dir(os):
            if name in process_names or name.startswith(("exec", "spawn")):
                loading.setattr(os, name, _forbidden)
        for name in ("signal", "pthread_sigmask", "setitimer", "alarm", "raise_signal"):
            loading.setattr(signal, name, _forbidden)
        spec.loader.exec_module(module)
    value.module = module
    module.os = _ProcessOS(value)
    module.signal = value.signals
    module.subprocess = SimpleNamespace(
        Popen=value.popen,
        PIPE=subprocess.PIPE,
        DEVNULL=subprocess.DEVNULL,
    )
    module.sys = SimpleNamespace(
        executable=sys.executable,
        version_info=(3, 12, 0),
        platform=sys.platform,
        flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1),
        argv=[],
    )
    module.time = _Clock()
    module.selectors = SimpleNamespace(
        DefaultSelector=_NoWaitSelector,
        EVENT_READ=selectors.EVENT_READ,
    )
    interpreter_pin = {"alias": sys.executable, "fixture_identity": "stable-fake-interpreter"}
    module.interpreter = lambda: interpreter_pin.copy()
    original_directory, original_persist = module.output_directory, module.persist

    def directory(path):
        fd, before = original_directory(path)
        value.root_fds.append(fd)
        return fd, before

    def persist(fd, root, report):
        value.reports.append(report)
        return original_persist(fd, root, report)

    module.output_directory = directory
    module.persist = persist
    module.write_all = lambda fd, payload: value.summaries.append((fd, payload))
    try:
        yield value
    finally:
        value.close()


def test_owned_child_assay_default_refuses_before_popen(rig, monkeypatch):
    with pytest.raises(SystemExit) as caught:
        rig.run(monkeypatch, execute=False)
    assert caught.value.code == 2
    assert rig.launches == rig.signals.calls == []
    assert not rig.root.exists()


def test_owned_child_assay_existing_output_refuses_before_popen(rig, monkeypatch):
    rig.root.mkdir(mode=0o700)
    sentinel = rig.root / "existing.txt"
    sentinel.write_bytes(b"preserve existing output")
    with pytest.raises(ValueError, match="already exists"):
        rig.run(monkeypatch)
    assert rig.launches == []
    assert sentinel.read_bytes() == b"preserve existing output"
    assert sorted(path.name for path in rig.root.iterdir()) == ["existing.txt"]


def test_owned_child_assay_fake_success_has_one_signal_wait_and_absence_probe(rig, monkeypatch):
    assert rig.run(monkeypatch) == 0
    report = rig.report()
    assert report["state"] == "INFORMATIONAL_PASS_NEW_LIVE_OWNED_GROUP_ONLY"
    assert rig.actions == ["KILL", "WAIT", "PROBE"]
    assert (report["signal_attempts"], report["wait_attempts"], report["group_probe_attempts"]) == (
        1,
        1,
        1,
    )
    assert report["returncode"] == -signal.SIGKILL
    assert report["faults"] == [] and report["group_absent"] is True
    assert report["pipes"]["eof"] == {"stdout": True, "stderr": True}
    assert bytes.fromhex(report["pipes"]["stdout_hex"]) == rig.child.ready
    assert report["pipes"]["stderr_hex"] == ""
    phases = [row["phase"] for row in report["events"]]
    assert phases.index("owned_identity_checked") < phases.index("killpg_enter")
    assert phases.index("killpg_return") < phases.index("wait_enter") < phases.index("wait_return")
    assert [call[0] for call in rig.signals.calls] == ["default", "unblock", "timer"]
    assert stat.S_IMODE(rig.root.stat().st_mode) == 0o500
    assert stat.S_IMODE((rig.root / "report.json").stat().st_mode) == 0o400
    assert len(rig.summaries) == 1 and rig.summaries[0][0] == 1
    summary = json.loads(rig.summaries[0][1])
    assert summary["report"]["bytes"] == (rig.root / "report.json").stat().st_size
    assert summary["state"] == report["state"]


def test_owned_child_assay_constructor_failure_has_no_returned_ownership(rig, monkeypatch):
    # This models an exception before Popen returns, not constructor internals.
    rig.constructor_error = PermissionError(errno.EACCES, "fake constructor denied")
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert len(rig.launches) == 1 and rig.child is None
    assert rig.module._OWNED_CHILD is None and rig.actions == rig.waits == []
    assert report["state"] == "INCOMPLETE_HOLD"
    assert (report["signal_attempts"], report["wait_attempts"], report["group_probe_attempts"]) == (
        0,
        0,
        0,
    )
    assert "reaped" not in report and "readiness" not in report and "pipes" not in report
    assert [event["phase"] for event in report["events"]] == ["popen_enter"]
    error = report["faults"][0]
    assert (error["phase"], error["type"], error["errno"]) == (
        "launch_readiness_or_signal",
        "PermissionError",
        errno.EACCES,
    )
    assert len(report["faults"]) == 1 and report["input_postchecks_passed"] is True
    assert json.loads(rig.summaries[0][1])["state"] == "INCOMPLETE_HOLD"


@pytest.mark.parametrize(
    "readiness",
    ["empty", "malformed", "foreign_parent", "foreign_pid", "bool_pid", "wrong_order"],
)
def test_owned_child_assay_bad_readiness_never_attempts_kill(rig, monkeypatch, readiness):
    rig.ready_kind = readiness
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert report["state"] == "INCOMPLETE_HOLD" and report["signal_attempts"] == 0
    assert rig.actions == ["WAIT", "PROBE"]
    assert report["faults"][0]["phase"] == "launch_readiness_or_signal"
    assert report["returncode"] == -signal.SIGALRM


@pytest.mark.parametrize("query", ["pgid", "sid"])
def test_owned_child_assay_foreign_session_query_never_attempts_kill(rig, monkeypatch, query):
    rig.foreign_query = query
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert report["signal_attempts"] == 0 and rig.actions == ["WAIT", "PROBE"]
    assert report["faults"][0]["message"] == "owned live-session eligibility differs"


def test_owned_child_assay_denied_kill_and_ttl_like_exit_remain_hold(rig, monkeypatch):
    rig.deny_kill = True
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert rig.actions == ["KILL", "WAIT", "PROBE"]
    assert report["returncode"] == -signal.SIGALRM and report["group_absent"] is True
    error = report["faults"][0]
    assert (error["type"], error["errno"]) == ("PermissionError", errno.EPERM)
    assert "kill_returned" not in report and report["state"] == "INCOMPLETE_HOLD"


def test_owned_child_assay_wait_timeout_has_no_second_wait_or_later_signal(rig, monkeypatch):
    rig.wait_timeout = True
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert rig.actions == ["KILL", "WAIT"] and len(rig.waits) == 1
    assert report["group_probe_attempts"] == 0 and "reaped" not in report
    assert report["faults"][0]["phase"] == "sole_wait"
    assert report["faults"][0]["type"] == "TimeoutExpired"
    assert rig.module._OWNED_CHILD is rig.child and rig.child.returncode is None


@pytest.mark.parametrize("probe", ["present", "denied"])
def test_owned_child_assay_group_probe_cannot_promote_hold(rig, monkeypatch, probe):
    rig.group_probe = probe
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert rig.actions == ["KILL", "WAIT", "PROBE"]
    assert report["state"] == "INCOMPLETE_HOLD"
    if probe == "present":
        assert report["group_absent"] is False and report["faults"] == []
    else:
        assert "group_absent" not in report
        assert report["faults"][0]["phase"] == "group_probe"
        assert report["faults"][0]["errno"] == errno.EPERM


def test_owned_child_assay_capture_cap_reports_unknown_tail(rig, monkeypatch):
    rig.module.RAW_LIMIT = len(rig.readiness()) + 8
    rig.tail = b"x" * 32
    assert rig.run(monkeypatch) == 1
    pipes = rig.report()["pipes"]
    captured = bytes.fromhex(pipes["stdout_hex"]) + bytes.fromhex(pipes["stderr_hex"])
    assert len(captured) == rig.module.RAW_LIMIT
    assert captured == (rig.child.ready + rig.tail)[: rig.module.RAW_LIMIT]
    assert pipes["cap_reached_tail_unknown"] is True
    assert pipes["eof"] != {"stdout": True, "stderr": True}
    assert rig.actions == ["KILL", "WAIT", "PROBE"]


def test_owned_child_assay_eof_is_not_inferred_from_reap(rig, monkeypatch):
    rig.missing_stderr_eof = True
    assert rig.run(monkeypatch) == 1
    report = rig.report()
    assert report["reaped"] is True and report["group_absent"] is True
    assert report["pipes"]["eof"] == {"stdout": True, "stderr": False}
    assert report["pipes"]["cap_reached_tail_unknown"] is False
    assert report["state"] == "INCOMPLETE_HOLD"


def test_owned_child_assay_fatal_persistence_propagates_without_cleanup_retry(rig, monkeypatch):
    def denied(*_args):
        raise PermissionError(errno.EACCES, "fake report persistence denied")

    rig.module.persist = denied
    with pytest.raises(PermissionError) as caught:
        rig.run(monkeypatch)
    assert caught.value.errno == errno.EACCES
    assert rig.actions == ["KILL", "WAIT", "PROBE"] and len(rig.waits) == 1
    assert rig.module._OWNED_CHILD is rig.child
    assert not (rig.root / "report.json").exists() and rig.summaries == []
    with pytest.raises(OSError) as closed:
        os.fstat(rig.root_fds[-1])
    assert closed.value.errno == errno.EBADF


def test_owned_child_assay_report_bound_failure_does_not_emit_passing_summary(rig, monkeypatch):
    rig.module.REPORT_LIMIT = 1
    with pytest.raises(ValueError, match="report bound"):
        rig.run(monkeypatch)
    assert rig.actions == ["KILL", "WAIT", "PROBE"]
    assert not (rig.root / "report.json").exists() and rig.summaries == []
    assert len(rig.reports) == 1


@pytest.mark.parametrize(
    ("platform", "uid", "expected"),
    [
        ("linux", 501, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}),
        (
            "darwin",
            501,
            {
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "TZ": "UTC",
                "__CF_USER_TEXT_ENCODING": "0x1F5:0x0:0x0",
            },
        ),
    ],
)
def test_owned_child_assay_execution_environment_is_exact_and_fresh(rig, platform, uid, expected):
    actual = rig.module.execution_environment(platform, uid)
    assert actual == expected and type(actual) is dict
    actual["TZ"] = "fixture mutation"
    assert rig.module.execution_environment(platform, uid) == expected
    assert rig.launches == rig.signals.calls == []


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong"])
def test_owned_child_assay_nonexact_environment_refuses_before_popen(rig, monkeypatch, mutation):
    reviewed = rig.module.ENVIRONMENT.copy()
    environment = rig.module.os.environ
    assert environment == reviewed and environment is not rig.module.ENVIRONMENT
    key = "__CF_USER_TEXT_ENCODING" if "__CF_USER_TEXT_ENCODING" in reviewed else "TZ"
    if mutation == "missing":
        del environment[key]
    elif mutation == "extra":
        environment["AQT_FAKE_UNEXPECTED"] = "must not be allowed"
    else:
        environment[key] = "wrong fixture value"
    with pytest.raises(ValueError, match="environment required"):
        rig.run(monkeypatch)
    assert reviewed == rig.module.ENVIRONMENT
    assert rig.launches == rig.actions == rig.waits == []
    assert rig.reports == rig.summaries == rig.root_fds == []
    assert rig.module._OWNED_CHILD is None and not rig.root.exists()
