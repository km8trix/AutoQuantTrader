"""Bounded test-only forwarding facts, with no clock or financial authority.

Keep this recorder separately from its wrapper. A caller may retain at most two
iteration recorders. Entry means an attempted forwarding lookup/call, not callee,
SQL or supervisor-site entry. Missing metadata is unavailable, never a negative
observation. Wrapper tracebacks and overhead cannot match an unwrapped call.
An allocation failure while building the unavailable snapshot can still escape
standalone snapshot(); summary() has a literal fallback. This is not universal
resource-exhaustion or replaced-private-primitive recovery.
"""

from __future__ import annotations

import json
import sys
from threading import Lock
from time import perf_counter_ns as _native_wall_time_ns
from time import thread_time_ns as _native_thread_time_ns

STAGES = ("prepare", "observe", "require_result")
COUNTER_CAP = 4096
SUMMARY_CAP = 4096
_FIELDS = ("entered", "returned", "raised", "active")
_KEYS = ("schema_version", "available", "incomplete", "overflow", "state", "stages")
_UNAVAILABLE = (
    '{"schema_version":1,"available":false,"incomplete":true,"overflow":false,'
    '"state":"unavailable","stages":null}'
)
_OVERFLOW = _UNAVAILABLE.replace('"overflow":false', '"overflow":true')


def _fail_closed(diagnostic: LifecycleForwardingDiagnostic, *, overflow: bool = False) -> None:
    # Native slots and fixed booleans avoid an arbitrary metadata error holder.
    try:
        object.__setattr__(diagnostic, "_incomplete", True)
        if overflow:
            object.__setattr__(diagnostic, "_overflow", True)
    except BaseException:
        # Metadata cannot become the forwarded operation's failure.
        pass


def _try_enter(diagnostic: LifecycleForwardingDiagnostic, stage: int) -> bool:
    try:
        entered = diagnostic._enter(stage)
        if type(entered) is bool and entered:
            return True
    except BaseException:
        pass
    _fail_closed(diagnostic)
    return False


def _try_leave(
    diagnostic: LifecycleForwardingDiagnostic, stage: int, *, entered: bool, returned: bool
) -> None:
    if not entered:
        return
    try:
        diagnostic._leave(stage, raised=not returned)
    except BaseException:
        _fail_closed(diagnostic)


def _scalar_snapshot(value: object) -> bool:
    """Admit only the fixed native snapshot before calling any serializer."""
    if type(value) is not dict or len(value) != len(_KEYS):
        return False
    keys = tuple(value)
    if any(type(key) is not str for key in keys) or keys != _KEYS:
        return False
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        return False
    if any(type(value[key]) is not bool for key in ("available", "incomplete", "overflow")):
        return False
    state = value["state"]
    if type(state) is not str:
        return False
    if not value["available"]:
        return value["incomplete"] and state == "unavailable" and value["stages"] is None
    if value["incomplete"] or value["overflow"]:
        return False
    stages = value["stages"]
    if type(stages) is not dict:
        return False
    stage_keys = tuple(stages)
    if any(type(key) is not str for key in stage_keys) or stage_keys != STAGES:
        return False
    entered = active = 0
    for stage in STAGES:
        row = stages[stage]
        if type(row) is not dict:
            return False
        row_keys = tuple(row)
        if any(type(key) is not str for key in row_keys) or row_keys != _FIELDS:
            return False
        if any(
            type(row[field]) is not int or not 0 <= row[field] <= COUNTER_CAP for field in _FIELDS
        ):
            return False
        if row["entered"] != row["returned"] + row["raised"] + row["active"]:
            return False
        entered += row["entered"]
        active += row["active"]
    return state == ("active" if active else "balanced" if entered else "empty")


_TIMING_FIELDS = (
    "completed_count",
    "wall_sum_ns",
    "wall_max_ns",
    "thread_cpu_sum_ns",
    "thread_cpu_max_ns",
)
_TIMING_KEYS = ("available", "overflow", "stages")
_CLOCK_CAP_NS = (1 << 63) - 1
_ELAPSED_CAP_NS = 10**15


def _release_timing_error(
    error, primary, traceback, cause, context, suppressed, *, restore_primary=True
):
    """Release only new native-clock edges; preserve the explicit operation error."""
    try:
        if error is not primary:
            error_suppressed = BaseException.__suppress_context__.__get__(error)
            BaseException.__traceback__.__set__(error, None)
            if BaseException.__cause__.__get__(error) is primary:
                BaseException.__cause__.__set__(error, None)
                BaseException.__suppress_context__.__set__(error, error_suppressed)
            if BaseException.__context__.__get__(error) is primary:
                BaseException.__context__.__set__(error, None)
        if restore_primary:
            BaseException.__traceback__.__set__(primary, traceback)
            BaseException.__cause__.__set__(primary, cause)
            BaseException.__context__.__set__(primary, context)
            BaseException.__suppress_context__.__set__(primary, suppressed)
    finally:
        error = primary = traceback = cause = context = suppressed = None


def _scalar_timing_snapshot(value: object) -> bool:
    if type(value) is not dict or len(value) != len(_KEYS) + 1:
        return False
    if any(type(key) is not str for key in value) or tuple(value) != (*_KEYS, "timing"):
        return False
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        return False
    plain = {key: value[key] for key in _KEYS}
    plain["schema_version"] = 1
    if not _scalar_snapshot(plain):
        return False
    timing = value["timing"]
    if type(timing) is not dict or len(timing) != len(_TIMING_KEYS):
        return False
    if any(type(key) is not str for key in timing) or tuple(timing) != _TIMING_KEYS:
        return False
    if type(timing["available"]) is not bool or type(timing["overflow"]) is not bool:
        return False
    if not timing["available"]:
        return timing["stages"] is None
    if timing["overflow"] or not value["available"]:
        return False
    rows = timing["stages"]
    if type(rows) is not dict or len(rows) != len(STAGES):
        return False
    if any(type(key) is not str for key in rows) or tuple(rows) != STAGES:
        return False
    for stage in STAGES:
        row = rows[stage]
        if type(row) is not dict or len(row) != len(_TIMING_FIELDS):
            return False
        if any(type(key) is not str for key in row) or tuple(row) != _TIMING_FIELDS:
            return False
        if (
            type(row["completed_count"]) is not int
            or not 0 <= row["completed_count"] <= COUNTER_CAP
        ):
            return False
        if any(
            type(row[k]) is not int or not 0 <= row[k] <= _ELAPSED_CAP_NS
            for k in _TIMING_FIELDS[1:]
        ):
            return False
        counts = value["stages"][stage]
        if row["completed_count"] != counts["returned"] + counts["raised"]:
            return False
        if (
            row["wall_max_ns"] > row["wall_sum_ns"]
            or row["thread_cpu_max_ns"] > row["thread_cpu_sum_ns"]
        ):
            return False
        if row["completed_count"] == 0 and any(row[k] for k in _TIMING_FIELDS[1:]):
            return False
    return True


def _try_timed_leave(diagnostic, stage, *, entered, returned, interval):
    if not entered:
        return
    try:
        diagnostic._leave(stage, raised=not returned, interval=interval)
    except BaseException:
        diagnostic._invalidate_timing()
        _fail_closed(diagnostic)
    finally:
        diagnostic = interval = None


class LifecycleForwardingDiagnostic:
    """Three fixed scalar rows; a lost transition permanently denies completeness."""

    __slots__ = (
        "_counts",
        "_incomplete",
        "_lock",
        "_native_timing",
        "_overflow",
        "_thread_clock_ns",
        "_timing",
        "_timing_overflow",
        "_timing_valid",
        "_wall_clock_ns",
    )

    def __init__(self, *, native_timing: bool = False) -> None:
        if type(native_timing) is not bool:
            raise TypeError("native_timing must be an exact bool")
        self._lock = Lock()
        self._counts = [[0, 0, 0, 0] for _ in STAGES]
        self._incomplete = False
        self._overflow = False
        self._native_timing = native_timing
        self._wall_clock_ns = _native_wall_time_ns if native_timing else None
        self._thread_clock_ns = _native_thread_time_ns if native_timing else None
        self._timing = [[0, 0, 0, 0, 0] for _ in STAGES] if native_timing else None
        self._timing_valid = native_timing
        self._timing_overflow = False

    def _invalidate_timing(self) -> None:
        self._timing_valid = False
        self._timing_overflow = True

    def _sample_timing(self, primary):
        values = traceback = cause = context = suppressed = None
        ownership_primary = primary
        snapshot_ready = False
        try:
            # Ambient ownership is cleanup-only. It never authorizes isolation
            # of a new interrupt when no original callback error is pending.
            if ownership_primary is None:
                ownership_primary = sys.exception()
            if ownership_primary is not None:
                traceback = BaseException.__traceback__.__get__(ownership_primary)
                cause = BaseException.__cause__.__get__(ownership_primary)
                context = BaseException.__context__.__get__(ownership_primary)
                suppressed = BaseException.__suppress_context__.__get__(ownership_primary)
                snapshot_ready = True
            values = (self._wall_clock_ns(), self._thread_clock_ns())
            if all(type(value) is int and 0 <= value <= _CLOCK_CAP_NS for value in values):
                return values
            self._invalidate_timing()
            return None
        except BaseException as error:
            self._invalidate_timing()
            if primary is None and type(error) is not OSError:
                raise
            if ownership_primary is None:
                BaseException.__traceback__.__set__(error, None)
            else:
                _release_timing_error(
                    error,
                    ownership_primary,
                    traceback,
                    cause,
                    context,
                    suppressed,
                    restore_primary=snapshot_ready,
                )
            return None
        finally:
            self = primary = ownership_primary = values = traceback = cause = context = (
                suppressed
            ) = None

    def _finish_timing(self, starts, primary):
        ends = interval = traceback = cause = context = suppressed = None
        snapshot_ready = False
        try:
            if primary is not None:
                traceback = BaseException.__traceback__.__get__(primary)
                cause = BaseException.__cause__.__get__(primary)
                context = BaseException.__context__.__get__(primary)
                suppressed = BaseException.__suppress_context__.__get__(primary)
                snapshot_ready = True
            ends = self._sample_timing(primary)
            if any(
                type(values) is not tuple
                or len(values) != 2
                or any(type(v) is not int or not 0 <= v <= _CLOCK_CAP_NS for v in values)
                for values in (starts, ends)
            ):
                self._invalidate_timing()
                return None
            interval = (ends[0] - starts[0], ends[1] - starts[1])
            if not all(type(value) is int and 0 <= value <= _ELAPSED_CAP_NS for value in interval):
                self._invalidate_timing()
                return None
            return interval
        except BaseException as error:
            self._invalidate_timing()
            if primary is None:
                raise
            _release_timing_error(
                error,
                primary,
                traceback,
                cause,
                context,
                suppressed,
                restore_primary=snapshot_ready,
            )
            return None
        finally:
            self = starts = primary = ends = interval = traceback = cause = context = suppressed = (
                None
            )

    def _update_timing(self, stage, interval):
        if not self._timing_valid:
            return
        if (
            type(interval) is not tuple
            or len(interval) != 2
            or any(type(v) is not int or not 0 <= v <= _ELAPSED_CAP_NS for v in interval)
        ):
            self._invalidate_timing()
            return
        row = self._timing[stage]
        if (
            type(row) is not list
            or len(row) != len(_TIMING_FIELDS)
            or any(type(v) is not int or not 0 <= v <= _ELAPSED_CAP_NS for v in row)
            or row[0] > COUNTER_CAP
        ):
            self._invalidate_timing()
            return
        completed, wall_sum, wall_max, thread_sum, thread_max = row
        updated = [
            completed + 1,
            wall_sum + interval[0],
            max(wall_max, interval[0]),
            thread_sum + interval[1],
            max(thread_max, interval[1]),
        ]
        if updated[0] > COUNTER_CAP or any(v > _ELAPSED_CAP_NS for v in updated[1:]):
            self._invalidate_timing()
            return
        self._timing[stage] = updated

    def _timing_snapshot(self):
        if not self._timing_valid:
            return {"available": False, "overflow": self._timing_overflow is True, "stages": None}
        rows = self._timing
        if (
            type(rows) is not list
            or len(rows) != len(STAGES)
            or any(
                type(row) is not list
                or len(row) != len(_TIMING_FIELDS)
                or any(type(v) is not int or not 0 <= v <= _ELAPSED_CAP_NS for v in row)
                or row[0] > COUNTER_CAP
                for row in rows
            )
        ):
            self._invalidate_timing()
            return {"available": False, "overflow": True, "stages": None}
        return {
            "available": True,
            "overflow": False,
            "stages": {
                stage: dict(zip(_TIMING_FIELDS, rows[index], strict=True))
                for index, stage in enumerate(STAGES)
            },
        }

    def _admit_snapshot(self, value):
        return _scalar_timing_snapshot(value) if self._native_timing else _scalar_snapshot(value)

    def _enter(self, stage: int) -> bool:
        lock = self._lock
        if self._incomplete:
            return False
        if not lock.acquire(blocking=False):
            _fail_closed(self)
            return False
        try:
            row = self._counts[stage]
            if row[0] >= COUNTER_CAP or row[3] >= COUNTER_CAP:
                _fail_closed(self, overflow=True)
                return False
            row[0] += 1
            row[3] += 1
            return True
        finally:
            lock.release()

    def _leave(self, stage: int, *, raised: bool, interval=None) -> None:
        lock = self._lock
        if self._incomplete:
            return
        if not lock.acquire(blocking=False):
            _fail_closed(self)
            return
        try:
            row = self._counts[stage]
            outcome = 2 if raised else 1
            if row[3] <= 0 or row[outcome] >= COUNTER_CAP:
                _fail_closed(self, overflow=row[outcome] >= COUNTER_CAP)
                return
            row[outcome] += 1
            row[3] -= 1
            if self._native_timing:
                self._update_timing(stage, interval)
        finally:
            lock.release()

    def _unavailable(self) -> dict[str, object]:
        if self._native_timing:
            return {
                "schema_version": 2,
                "available": False,
                "incomplete": True,
                "overflow": self._overflow is True,
                "state": "unavailable",
                "stages": None,
                "timing": {
                    "available": False,
                    "overflow": self._timing_overflow is True,
                    "stages": None,
                },
            }
        return {
            "schema_version": 1,
            "available": False,
            "incomplete": True,
            "overflow": self._overflow is True,
            "state": "unavailable",
            "stages": None,
        }

    def snapshot(self) -> dict[str, object]:
        """Copy under a nonblocking lock; no user callbacks occur while it is held."""
        try:
            lock = self._lock
            if self._incomplete:
                return self._unavailable()
            if not lock.acquire(blocking=False):
                _fail_closed(self)
                return self._unavailable()
            try:
                rows = self._counts
                if type(rows) is not list or len(rows) != len(STAGES):
                    _fail_closed(self)
                    return self._unavailable()
                stages = {}
                for index, stage in enumerate(STAGES):
                    row = rows[index]
                    if type(row) is not list or len(row) != len(_FIELDS):
                        _fail_closed(self)
                        return self._unavailable()
                    if any(
                        type(count) is not int or not 0 <= count <= COUNTER_CAP for count in row
                    ):
                        _fail_closed(self)
                        return self._unavailable()
                    stages[stage] = dict(zip(_FIELDS, row, strict=True))
                entered = sum(row["entered"] for row in stages.values())
                active = sum(row["active"] for row in stages.values())
                snapshot = {
                    "schema_version": 1,
                    "available": True,
                    "incomplete": False,
                    "overflow": False,
                    "state": "active" if active else "balanced" if entered else "empty",
                    "stages": stages,
                }
                if self._native_timing:
                    snapshot["schema_version"] = 2
                    snapshot["timing"] = self._timing_snapshot()
                if not self._admit_snapshot(snapshot) or self._incomplete:
                    _fail_closed(self)
                    return self._unavailable()
                return snapshot
            finally:
                lock.release()
        except BaseException:
            _fail_closed(self)
            return self._unavailable()

    def _fallback_summary(self):
        root_overflow = "true" if self._overflow is True else "false"
        timing_overflow = "true" if self._timing_overflow is True else "false"
        return (
            '{"schema_version":2,"available":false,"incomplete":true,"overflow":'
            + root_overflow
            + ',"state":"unavailable","stages":null,'
            '"timing":{"available":false,"overflow":' + timing_overflow + ',"stages":null}}'
        )

    def summary(self) -> str:
        """Serialize only admitted scalar copies after the lock has been released."""
        snapshot = None
        try:
            snapshot = self.snapshot()
            if not self._admit_snapshot(snapshot):
                _fail_closed(self)
                return (
                    self._fallback_summary()
                    if self._native_timing
                    else (_OVERFLOW if self._overflow is True else _UNAVAILABLE)
                )
            text = json.dumps(snapshot, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            if type(text) is not str or len(text.encode("utf-8")) > SUMMARY_CAP:
                _fail_closed(self)
                return (
                    self._fallback_summary()
                    if self._native_timing
                    else (_OVERFLOW if self._overflow is True else _UNAVAILABLE)
                )
            return text
        except BaseException:
            _fail_closed(self)
            return (
                self._fallback_summary()
                if self._native_timing
                else (_OVERFLOW if self._overflow is True else _UNAVAILABLE)
            )
        finally:
            self = snapshot = None


_TIMING_RECORDER_TYPE = LifecycleForwardingDiagnostic


def _native_timing_enabled(diagnostic) -> bool:
    try:
        return (
            type(diagnostic) is _TIMING_RECORDER_TYPE
            and object.__getattribute__(diagnostic, "_native_timing") is True
        )
    except BaseException:
        return False
    finally:
        diagnostic = None


class ObservedLifecycle:
    """Forward each port once with dynamic lookup and no private recorder values."""

    __slots__ = ("__weakref__", "_delegate", "_diagnostic")

    def __init__(self, delegate: object, diagnostic: LifecycleForwardingDiagnostic) -> None:
        self._delegate = delegate
        self._diagnostic = diagnostic

    def prepare(self, startup: object) -> object:
        if _native_timing_enabled(self._diagnostic):
            try:
                return self._timed_forward(0, startup)
            finally:
                self = startup = None
        delegate = diagnostic = result = None
        entered = returned = False
        try:
            delegate, diagnostic = self._delegate, self._diagnostic
            try:
                entered = _try_enter(diagnostic, 0)
            except BaseException:
                _fail_closed(diagnostic)
            result = delegate.prepare(startup)
            returned = True
            return result
        finally:
            try:
                _try_leave(diagnostic, 0, entered=entered, returned=returned)
            except BaseException:
                _fail_closed(diagnostic)
            finally:
                self = delegate = diagnostic = startup = result = None

    def observe(self, *, child_pid: object, child_exited: object) -> object:
        if _native_timing_enabled(self._diagnostic):
            try:
                return self._timed_forward(1, child_pid, child_exited)
            finally:
                self = child_pid = child_exited = None
        delegate = diagnostic = result = None
        entered = returned = False
        try:
            delegate, diagnostic = self._delegate, self._diagnostic
            try:
                entered = _try_enter(diagnostic, 1)
            except BaseException:
                _fail_closed(diagnostic)
            result = delegate.observe(child_pid=child_pid, child_exited=child_exited)
            returned = True
            return result
        finally:
            try:
                _try_leave(diagnostic, 1, entered=entered, returned=returned)
            except BaseException:
                _fail_closed(diagnostic)
            finally:
                self = delegate = diagnostic = child_pid = child_exited = result = None

    def require_result(self, payload: object) -> object:
        if _native_timing_enabled(self._diagnostic):
            try:
                return self._timed_forward(2, payload)
            finally:
                self = payload = None
        delegate = diagnostic = result = None
        entered = returned = False
        try:
            delegate, diagnostic = self._delegate, self._diagnostic
            try:
                entered = _try_enter(diagnostic, 2)
            except BaseException:
                _fail_closed(diagnostic)
            result = delegate.require_result(payload)
            returned = True
            return result
        finally:
            try:
                _try_leave(diagnostic, 2, entered=entered, returned=returned)
            except BaseException:
                _fail_closed(diagnostic)
            finally:
                self = delegate = diagnostic = payload = result = None

    def _timed_forward(self, stage, first, second=None):
        delegate = diagnostic = result = starts = interval = None
        entered = returned = False
        try:
            delegate, diagnostic = self._delegate, self._diagnostic
            try:
                entered = _try_enter(diagnostic, stage)
            except BaseException:
                _fail_closed(diagnostic)
            if not entered:
                diagnostic._invalidate_timing()
            starts = diagnostic._sample_timing(None) if entered else None
            try:
                if stage == 0:
                    result = delegate.prepare(first)
                elif stage == 1:
                    result = delegate.observe(child_pid=first, child_exited=second)
                else:
                    result = delegate.require_result(first)
            except BaseException as primary:
                interval = diagnostic._finish_timing(starts, primary) if entered else None
                raise
            else:
                returned = True
                interval = diagnostic._finish_timing(starts, None) if entered else None
                return result
        finally:
            try:
                _try_timed_leave(
                    diagnostic, stage, entered=entered, returned=returned, interval=interval
                )
            finally:
                self = delegate = diagnostic = result = starts = interval = first = second = None
