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
from threading import Lock

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


class LifecycleForwardingDiagnostic:
    """Three fixed scalar rows; a lost transition permanently denies completeness."""

    __slots__ = ("_counts", "_incomplete", "_lock", "_overflow")

    def __init__(self) -> None:
        self._lock = Lock()
        self._counts = [[0, 0, 0, 0] for _ in STAGES]
        self._incomplete = False
        self._overflow = False

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

    def _leave(self, stage: int, *, raised: bool) -> None:
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
        finally:
            lock.release()

    def _unavailable(self) -> dict[str, object]:
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
                if not _scalar_snapshot(snapshot) or self._incomplete:
                    _fail_closed(self)
                    return self._unavailable()
                return snapshot
            finally:
                lock.release()
        except BaseException:
            _fail_closed(self)
            return self._unavailable()

    def summary(self) -> str:
        """Serialize only admitted scalar copies after the lock has been released."""
        snapshot = None
        try:
            snapshot = self.snapshot()
            if not _scalar_snapshot(snapshot):
                _fail_closed(self)
                return _OVERFLOW if self._overflow is True else _UNAVAILABLE
            text = json.dumps(snapshot, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            if type(text) is not str or len(text.encode("utf-8")) > SUMMARY_CAP:
                _fail_closed(self)
                return _OVERFLOW if self._overflow is True else _UNAVAILABLE
            return text
        except BaseException:
            _fail_closed(self)
            return _OVERFLOW if self._overflow is True else _UNAVAILABLE
        finally:
            self = snapshot = None


class ObservedLifecycle:
    """Forward each port once with dynamic lookup and no private recorder values."""

    __slots__ = ("__weakref__", "_delegate", "_diagnostic")

    def __init__(self, delegate: object, diagnostic: LifecycleForwardingDiagnostic) -> None:
        self._delegate = delegate
        self._diagnostic = diagnostic

    def prepare(self, startup: object) -> object:
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
