"""Linux status observation preserves bounded state/RSS and sole-waiter ownership."""

import os
import select
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from packages.application import continuous_process as process_module

_PID = 1234
_CAP = 16 * 1024
_STATUS_END = b"nonvoluntary_ctxt_switches:\t0\n"


def _status(*, state=b"S", rss=b"17 kB", pid=b"1234", tgid=b"1234", extra=b""):
    rows = b"Name:\tfixture (\\n)\\\\name\n"
    rows += b"State:\t" + state + b" (fixture)\n"
    rows += b"Tgid:\t" + tgid + b"\nPid:\t" + pid + b"\n"
    if rss is not None:
        rows += b"VmRSS:\t" + rss + b"\n"
    return rows + extra + _STATUS_END


@pytest.mark.parametrize("state", [b"D", b"I", b"R", b"S", b"T", b"U", b"W", b"Z"])
@pytest.mark.parametrize("kilobytes", [0, 1, 1024, 524289])
def test_linux_status_preserves_existing_states_and_current_rss(state, kilobytes):
    value = process_module._parse_linux_child_status(
        _status(state=state, rss=str(kilobytes).encode() + b" kB"), _PID
    )
    assert value == process_module._ChildObservation(state == b"Z", kilobytes * 1024)
    assert type(value.exited) is bool and type(value.resident_bytes) is int


def test_linux_current_rss_is_not_peak_virtual_or_component_sum():
    payload = _status(
        rss=b"3 kB",
        extra=b"VmHWM:\t9999 kB\nVmSize:\t7777 kB\nRssAnon:\t11 kB\n"
        b"RssFile:\t22 kB\nRssShmem:\t33 kB\n",
    )
    assert process_module._parse_linux_child_status(payload, _PID).resident_bytes == 3072


@pytest.mark.parametrize("digits", [20, 21])
def test_linux_rss_decimal_field_has_a_finite_twenty_digit_bound(digits):
    payload = _status(rss=b"9" * digits + b" kB")
    if digits == 20:
        assert process_module._parse_linux_child_status(payload, _PID).resident_bytes == (
            int(b"9" * digits) * 1024
        )
    else:
        with pytest.raises(ValueError):
            process_module._parse_linux_child_status(payload, _PID)


@pytest.mark.parametrize("name", [b"arbitrary\xff\xfe", b"carriage\rreturn", b"paren (name)\\n"])
def test_linux_unrelated_name_bytes_are_not_decoded_or_used_as_state(name):
    payload = b"Name:\t" + name + b"\n" + _status().split(b"\n", 1)[1]
    assert process_module._parse_linux_child_status(payload, _PID) == (
        process_module._ChildObservation(False, 17 * 1024)
    )


@pytest.mark.parametrize("state", [b"Z", b"R", b"S", b"T"])
def test_linux_complete_no_memory_section_is_zero_but_only_z_is_exit(state):
    result = process_module._parse_linux_child_status(_status(state=state, rss=None), _PID)
    assert result == process_module._ChildObservation(state == b"Z", 0)


@pytest.mark.parametrize(
    "field",
    [
        b"VmPeak",
        b"VmSize",
        b"VmHWM",
        b"VmData",
        b"VmUnknown",
        b"RssAnon",
        b"RssFile",
        b"RssShmem",
        b"RssUnknown",
        b"HugetlbPages",
        b"CoreDumping",
        b"THP_enabled",
        b"untag_mask",
    ],
)
def test_linux_partial_memory_section_cannot_manufacture_zero_rss(field):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(
            _status(state=b"Z", rss=None, extra=field + b":\t0\n"), _PID
        )


@pytest.mark.parametrize("state", [b"t", b"X", b"x", b"P", b"?", b"SS", b"", b"Z+"])
def test_linux_unknown_or_nonoriginal_state_is_not_exit(state):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status(state=state), _PID)


@pytest.mark.parametrize(
    "rss",
    [
        b"",
        b"1",
        b"1 KB",
        b"1 B",
        b"-1 kB",
        b"+1 kB",
        b"1.5 kB",
        b"x kB",
        b"1 kB extra",
        "\N{FULLWIDTH DIGIT ONE} kB".encode(),
        b"9" * 5000 + b" kB",
    ],
)
def test_linux_malformed_rss_does_not_fall_back_to_zero(rss):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status(state=b"Z", rss=rss), _PID)


@pytest.mark.parametrize("field", [b"Pid", b"Tgid", b"State", b"VmRSS"])
@pytest.mark.parametrize("conflicting", [False, True])
def test_linux_duplicate_relevant_rows_reject_equal_and_conflicting_values(field, conflicting):
    values = {b"Pid": b"1234", b"Tgid": b"1234", b"State": b"S (fixture)", b"VmRSS": b"17 kB"}
    extra = field + b":\t" + (b"other" if conflicting else values[field]) + b"\n"
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status(extra=extra), _PID)


@pytest.mark.parametrize("field", [b"Pid", b"Tgid", b"State"])
def test_linux_missing_identity_or_state_is_unavailable(field):
    payload = b"\n".join(row for row in _status().split(b"\n") if not row.startswith(field + b":"))
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(payload, _PID)


@pytest.mark.parametrize("field", ["pid", "tgid"])
@pytest.mark.parametrize("value", [b"0", b"1235", b"-1234", b"+1234", b"12.34", b"1234 extra"])
def test_linux_status_identity_must_match_original_positive_child(field, value):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status(**{field: value}), _PID)


def test_linux_unrelated_fields_and_order_do_not_change_the_selected_pair():
    payload = _status(extra=b"Threads:\t2\nvoluntary_ctxt_switches:\t9\n")
    prefix = payload.removesuffix(_STATUS_END)
    reordered = b"\n".join(reversed(prefix.rstrip(b"\n").split(b"\n"))) + b"\n" + _STATUS_END
    assert process_module._parse_linux_child_status(reordered, _PID) == (
        process_module._ChildObservation(False, 17 * 1024)
    )


@pytest.mark.parametrize("payload", [b"", _status()[:-1], b"not-a-status-row\n", _status() + b"\n"])
def test_linux_incomplete_or_malformed_record_is_unavailable(payload):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(payload, _PID)


@pytest.mark.parametrize(
    "state_row",
    [b"State: S\n", b"State: S ()\n", b"State: S (bad(extra))\n", b"State: S (bad\x00)\n"],
)
def test_linux_state_requires_original_code_and_complete_description(state_row):
    payload = _status().replace(b"State:\tS (fixture)\n", state_row)
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(payload, _PID)


@pytest.mark.parametrize("pid", [True, 0, -1, "1234"])
def test_linux_parser_identity_requires_exact_positive_integer(pid):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status(), pid)


@pytest.mark.parametrize("rss", [None, b"17 kB"])
def test_linux_newline_prefix_before_late_kernel_marker_is_not_complete(rss):
    prefix = _status(rss=rss).removesuffix(_STATUS_END)
    assert prefix.endswith(b"\n")
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(prefix, _PID)


@pytest.mark.parametrize(
    "value", [b"", b"-1", b"+1", b"1.5", b"1 extra", b"1 kB", b"9" * 21, b"\xff"]
)
def test_linux_late_marker_has_one_bounded_unsigned_decimal(value):
    payload = _status().replace(_STATUS_END, b"nonvoluntary_ctxt_switches:\t" + value + b"\n")
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(payload, _PID)


@pytest.mark.parametrize("value", [b"0", b"9" * 20])
def test_linux_late_marker_counts_do_not_change_observation(value):
    payload = _status().replace(_STATUS_END, b"nonvoluntary_ctxt_switches:\t" + value + b"\n")
    assert process_module._parse_linux_child_status(payload, _PID) == (
        process_module._ChildObservation(False, 17 * 1024)
    )


@pytest.mark.parametrize("second", [_STATUS_END, b"nonvoluntary_ctxt_switches:\t1\n"])
def test_linux_late_marker_cannot_repeat_even_with_equal_value(second):
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(_status() + second, _PID)


@pytest.mark.parametrize(
    "field", [b"State", b"Pid", b"Tgid", b"VmRSS", b"VmHWM", b"RssAnon", b"CoreDumping"]
)
def test_linux_late_marker_must_follow_all_selected_identity_state_and_memory_rows(field):
    payload = _status(extra=b"VmHWM:\t20 kB\nRssAnon:\t1 kB\nCoreDumping:\t0\n")
    rows = payload.splitlines(keepends=True)
    moved = next(row for row in rows if row.startswith(field + b":"))
    rows.remove(moved)
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(b"".join(rows) + moved, _PID)


def test_linux_unrelated_architecture_tail_after_marker_is_allowed():
    assert process_module._parse_linux_child_status(
        _status() + b"arch_specific_fixture:\t1\n", _PID
    ) == process_module._ChildObservation(False, 17 * 1024)


@pytest.mark.parametrize(
    "key",
    [
        b" VmRSS",
        b"VmRSS ",
        b"\tVmRSS",
        b"Vm-RSS",
        b"Vm.RSS",
        b"VmRSS\r",
        b"\xffVmRSS",
        b"1VmRSS",
        b"VmRSS\x00",
    ],
)
@pytest.mark.parametrize("after_marker", [False, True])
def test_linux_invalid_status_key_cannot_hide_malformed_memory_as_unrelated(key, after_marker):
    row = key + b": bad\n"
    payload = _status(rss=None) + row if after_marker else _status(rss=None, extra=row)
    with pytest.raises(ValueError):
        process_module._parse_linux_child_status(payload, _PID)


def test_linux_valid_identifier_keys_keep_unrelated_values_opaque():
    payload = _status(extra=b"_fixture2:\t\xff value: with spaces\n") + b"arch_Feature2:\t0\n"
    assert process_module._parse_linux_child_status(payload, _PID) == (
        process_module._ChildObservation(False, 17 * 1024)
    )


@pytest.mark.parametrize("platform,selected", [("linux", "native"), ("darwin", "ps")])
def test_dispatch_preserves_pid_and_original_timeout(monkeypatch, platform, selected):
    calls = []
    expected = process_module._ChildObservation(False, 11)

    def native(pid, *, timeout):
        calls.append(("native", pid, timeout))
        return expected

    def ps(pid, *, timeout):
        calls.append(("ps", pid, timeout))
        return expected

    monkeypatch.setattr(process_module, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(process_module, "_observe_linux_child", native)
    monkeypatch.setattr(process_module, "_observe_ps_child", ps)
    assert process_module._observe_child(_PID, timeout=0.03125) is expected
    assert calls == [(selected, _PID, 0.03125)]


@pytest.mark.parametrize("error_type", [ValueError, OSError, subprocess.TimeoutExpired])
def test_linux_failure_never_falls_back_to_ps_or_retries(monkeypatch, error_type):
    calls = []
    error = (
        error_type("fixture", 0.01)
        if error_type is subprocess.TimeoutExpired
        else error_type("fixture")
    )

    def native(pid, *, timeout):
        calls.append((pid, timeout))
        raise error

    def forbidden(*args, **kwargs):
        raise AssertionError("native failure must not create another observation")

    monkeypatch.setattr(process_module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(process_module, "_observe_linux_child", native)
    monkeypatch.setattr(process_module, "_observe_ps_child", forbidden)
    with pytest.raises(error_type) as caught:
        process_module._observe_child(_PID, timeout=0.01)
    assert caught.value is error
    assert calls == [(_PID, 0.01)]


class _FileModel:
    def __init__(self, payload):
        self.remaining = payload
        self.calls = []
        self.clock = 0.0
        self.mode = stat.S_IFREG | 0o444
        self.chunk_size = None
        self.error_at = None
        self.error = OSError("fixture IO failure")
        self.advance_at = None
        self.advance = 0.0

    def _step(self, operation):
        if self.advance_at == operation:
            self.clock += self.advance
        if self.error_at == operation:
            raise self.error

    def open(self, path, flags):
        self.calls.append(("open", path, flags))
        self._step("open")
        return 41

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        self._step("fstat")
        return SimpleNamespace(st_mode=self.mode, st_size=0)

    def read(self, fd, limit):
        self.calls.append(("read", fd, limit))
        self._step("read")
        if self.chunk_size is not None:
            limit = min(limit, self.chunk_size)
        result, self.remaining = self.remaining[:limit], self.remaining[limit:]
        return result

    def close(self, fd):
        self.calls.append(("close", fd))
        self._step("close")


@pytest.fixture
def file_model(monkeypatch):
    model = _FileModel(_status())
    fake_os = SimpleNamespace(**vars(os))
    for operation in ("open", "fstat", "read", "close"):
        setattr(fake_os, operation, getattr(model, operation))
    monkeypatch.setattr(process_module, "os", fake_os)
    monkeypatch.setattr(process_module, "time", SimpleNamespace(monotonic=lambda: model.clock))
    return model


def test_linux_io_uses_one_bounded_nonfollowing_regular_file_and_closes(file_model):
    result = process_module._observe_linux_child(_PID, timeout=0.1)
    assert result == process_module._ChildObservation(False, 17 * 1024)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    assert file_model.calls[0] == ("open", "/proc/1234/status", flags)
    assert file_model.calls[1] == ("fstat", 41)
    assert [call for call in file_model.calls if call[0] == "close"] == [("close", 41)]
    assert all(0 < call[2] <= _CAP + 1 for call in file_model.calls if call[0] == "read")


def test_linux_short_reads_are_progress_under_one_fd_and_one_byte_bound(file_model):
    file_model.chunk_size = 7
    assert process_module._observe_linux_child(_PID, timeout=0.1).resident_bytes == 17 * 1024
    assert sum(call[0] == "open" for call in file_model.calls) == 1
    assert sum(call[0] == "close" for call in file_model.calls) == 1
    assert len([call for call in file_model.calls if call[0] == "read"]) > 2


@pytest.mark.parametrize("length", [_CAP, _CAP + 1])
def test_linux_total_status_bound_is_independent_of_procfs_zero_st_size(file_model, length):
    base = _status()
    file_model.remaining = base + b"Ignored:\t" + b"x" * (length - len(base) - 10) + b"\n"
    assert len(file_model.remaining) == length
    if length == _CAP:
        assert process_module._observe_linux_child(_PID, timeout=0.1).resident_bytes == 17 * 1024
    else:
        with pytest.raises(ValueError):
            process_module._observe_linux_child(_PID, timeout=0.1)
    assert file_model.calls[-1] == ("close", 41)


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK])
def test_linux_nonregular_descriptor_rejected_before_read(file_model, mode):
    file_model.mode = mode
    with pytest.raises(ValueError):
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert not any(call[0] == "read" for call in file_model.calls)
    assert file_model.calls[-1] == ("close", 41)


@pytest.mark.parametrize("error_type", [FileNotFoundError, PermissionError, BlockingIOError])
def test_linux_absent_denied_or_nonblocking_error_is_not_exit(file_model, error_type):
    file_model.error_at = "open"
    file_model.error = error_type("fixture status unavailable")
    with pytest.raises(error_type) as caught:
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert caught.value is file_model.error
    assert len(file_model.calls) == 1


@pytest.mark.parametrize("operation", ["open", "fstat", "read", "close"])
def test_linux_io_failure_identity_survives_later_deadline(file_model, operation):
    file_model.error_at = file_model.advance_at = operation
    file_model.advance = 1.0
    with pytest.raises(OSError) as caught:
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert caught.value is file_model.error
    assert sum(call[0] == "close" for call in file_model.calls) == (operation != "open")


def test_linux_primary_read_error_survives_secondary_close_error(file_model, monkeypatch):
    file_model.error_at = "read"

    def close(fd):
        file_model.calls.append(("close", fd))
        file_model.clock = 1.0
        raise OSError("secondary close failure")

    monkeypatch.setattr(process_module.os, "close", close)
    with pytest.raises(OSError) as caught:
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert caught.value is file_model.error
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert file_model.calls[-1] == ("close", 41)


def test_linux_primary_parser_error_survives_secondary_close_error(file_model, monkeypatch):
    error = ValueError("primary parser failure")

    def parse(payload, pid):
        raise error

    def close(fd):
        file_model.calls.append(("close", fd))
        file_model.clock = 1.0
        raise OSError("secondary close failure")

    monkeypatch.setattr(process_module, "_parse_linux_child_status", parse)
    monkeypatch.setattr(process_module.os, "close", close)
    with pytest.raises(ValueError) as caught:
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert caught.value is error
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert file_model.calls[-1] == ("close", 41)


@pytest.mark.parametrize("payload", [b"", b"Name:\ttruncated\n", _status(rss=b"invalid")])
def test_linux_unavailable_payload_still_closes(file_model, payload):
    file_model.remaining = payload
    with pytest.raises(ValueError):
        process_module._observe_linux_child(_PID, timeout=0.1)
    assert file_model.calls[-1] == ("close", 41)


@pytest.mark.parametrize("timeout", [0.0, -0.01])
def test_linux_no_remaining_budget_does_not_open_status(file_model, timeout):
    with pytest.raises(subprocess.TimeoutExpired):
        process_module._observe_linux_child(_PID, timeout=timeout)
    assert file_model.calls == []


@pytest.mark.parametrize("operation", ["open", "fstat", "read", "close"])
@pytest.mark.parametrize("timeout", [0.1, 0.03125])
def test_linux_deadline_equality_never_returns_success(file_model, operation, timeout):
    file_model.advance_at, file_model.advance = operation, timeout
    with pytest.raises(subprocess.TimeoutExpired):
        process_module._observe_linux_child(_PID, timeout=timeout)
    assert file_model.calls[-1] == ("close", 41)


@pytest.mark.parametrize("raises", [False, True])
def test_linux_parser_error_precedes_later_clock_but_success_cannot_be_late(
    file_model, monkeypatch, raises
):
    original = process_module._parse_linux_child_status
    error = ValueError("fixture parser failure")

    def parse(payload, pid):
        file_model.clock = 0.1
        if raises:
            raise error
        return original(payload, pid)

    monkeypatch.setattr(process_module, "_parse_linux_child_status", parse)
    with pytest.raises(ValueError if raises else subprocess.TimeoutExpired) as caught:
        process_module._observe_linux_child(_PID, timeout=0.1)
    if raises:
        assert caught.value is error
    assert file_model.calls[-1] == ("close", 41)


@contextmanager
def _owned_linux_child():
    # Only this child and its pipes; no repository service or provider is started.
    child = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import os; os.write(1,b'ready\\n'); os.read(0,1)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        close_fds=True,
    )
    try:
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 2.0)
        assert ready and child.stdout.readline() == b"ready\n"
        yield child
    finally:
        if child.returncode is None:
            # Signals only target the still-owned unreaped original PID.
            try:
                os.kill(child.pid, signal.SIGCONT)
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2.0)
        for pipe in (child.stdin, child.stdout):
            if pipe is not None:
                pipe.close()


def _without_observation_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("observation cannot spawn ps, signal, poll or reap")

    fake_os = SimpleNamespace(**vars(os))
    for name in ("waitpid", "waitid", "kill", "killpg"):
        if hasattr(fake_os, name):
            setattr(fake_os, name, forbidden)
    monkeypatch.setattr(process_module, "os", fake_os)
    monkeypatch.setattr(
        process_module,
        "subprocess",
        SimpleNamespace(
            run=forbidden,
            Popen=forbidden,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )


@pytest.mark.skipif(
    sys.platform != "linux", reason="requires actual Linux procfs for an owned child"
)
def test_actual_linux_live_child_current_rss_does_not_reap_or_launch_ps(monkeypatch):
    with _owned_linux_child() as child:
        with monkeypatch.context() as observation:
            _without_observation_effects(observation)
            result = process_module._observe_linux_child(child.pid, timeout=0.1)
        assert result.exited is False
        assert type(result.resident_bytes) is int and result.resident_bytes >= 0
        assert child.returncode is None


@pytest.mark.skipif(
    sys.platform != "linux", reason="requires actual Linux procfs for an owned child"
)
def test_actual_linux_stopped_child_is_not_exit(monkeypatch):
    with _owned_linux_child() as child:
        os.kill(child.pid, signal.SIGSTOP)
        # WNOWAIT is deliberately not used: even nonreaping wait machinery is outside observation.
        deadline = time.monotonic() + 2.0
        while True:
            with open(f"/proc/{child.pid}/status", "rb") as stream:
                payload = stream.read(_CAP + 1)
            if b"State:\tT" in payload:
                break
            assert time.monotonic() < deadline, "owned child did not enter stopped state"
            time.sleep(0.01)
        with monkeypatch.context() as observation:
            _without_observation_effects(observation)
            result = process_module._observe_linux_child(child.pid, timeout=0.1)
        assert result.exited is False and child.returncode is None


@pytest.mark.skipif(
    sys.platform != "linux", reason="requires actual Linux procfs for an owned child"
)
def test_actual_linux_zombie_is_observed_before_single_original_owner_wait(monkeypatch):
    with _owned_linux_child() as child:
        assert child.stdin is not None
        child.stdin.write(b"x")
        child.stdin.flush()
        deadline = time.monotonic() + 2.0
        with monkeypatch.context() as observation:
            _without_observation_effects(observation)
            while True:
                result = process_module._observe_linux_child(child.pid, timeout=0.1)
                if result.exited:
                    break
                assert time.monotonic() < deadline, "owned child did not become an unreaped zombie"
                time.sleep(0.01)
        assert result.resident_bytes == 0 and child.returncode is None
        assert child.wait(timeout=2.0) == 0
