"""Test-only two-iteration forwarding snapshots and a bounded failure line.

Wrap a delegate only after its original constructor has run. Setup is caller-owned
and single-threaded; callbacks use the existing nonblocking scalar recorder.
Snapshots are separate observations, not an atomic two-iteration epoch. Forwarding
entry establishes neither callee/SQL entry nor a cause, elapsed time or authority.
Missing output and unavailable slots are unknown. This fixture does not promise
recovery from universal resource exhaustion or replaced private primitives.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from tests.fixtures.lifecycle_forwarding_diagnostic import (
    LifecycleForwardingDiagnostic,
    ObservedLifecycle,
    _scalar_snapshot,
)

LINE_CAP = 4096
PREFIX = "AQT_PARENT_LIFECYCLE_DIAGNOSTIC "
_KEYS = ("schema_version", "current_iteration", "misused", "iterations")
_UNKNOWN = (
    '{"schema_version":1,"available":false,"incomplete":true,"overflow":false,'
    '"state":"unavailable","stages":null}'
)


class ParentLifecycleDiagnostics:
    """Only two None/False/exact-recorder slots and a sticky setup-misuse flag."""

    __slots__ = ("__weakref__", "_misused", "_slots")

    def __init__(self) -> None:
        self._slots: list[LifecycleForwardingDiagnostic | None | bool] = [None, None]
        self._misused = False


# Exact admission remains independent of injectable constructors in unit tests.
_MANAGER_TYPE = ParentLifecycleDiagnostics
_RECORDER_TYPE = LifecycleForwardingDiagnostic
_WRAPPER_TYPE = ObservedLifecycle


def create_parent_diagnostics() -> ParentLifecycleDiagnostics | None:
    manager = None
    try:
        manager = ParentLifecycleDiagnostics()
        return manager if type(manager) is _MANAGER_TYPE else None
    except BaseException:
        return None
    finally:
        manager = None


def _iteration(value: object) -> bool:
    return type(value) is int and value in (1, 2)


def _mark_misused(manager: ParentLifecycleDiagnostics) -> None:
    try:
        object.__setattr__(manager, "_misused", True)
    except BaseException:
        pass
    finally:
        manager = None


def _slots_valid(slots: object) -> bool:
    return (
        type(slots) is list
        and len(slots) == 2
        and all(slot is None or slot is False or type(slot) is _RECORDER_TYPE for slot in slots)
    )


def wrap_already_constructed(
    delegate: Any, *, diagnostics: ParentLifecycleDiagnostics | None, iteration: object
) -> Any:
    """Return the original delegate on new faults; never catch its construction."""
    slots = recorder = wrapped = None
    try:
        if type(diagnostics) is not _MANAGER_TYPE:
            return delegate
        if not _iteration(iteration):
            _mark_misused(diagnostics)
            return delegate
        slots = diagnostics._slots
        if not _slots_valid(slots) or diagnostics._misused is not False:
            _mark_misused(diagnostics)
            return delegate
        index = iteration - 1
        if slots[index] is not None:
            _mark_misused(diagnostics)
            return delegate
        # Reserve before constructors: duplicate/reentrant attempts cannot allocate
        # a third recorder or replace an earlier successful slot.
        slots[index] = False
        recorder = LifecycleForwardingDiagnostic()
        if type(recorder) is not _RECORDER_TYPE:
            return delegate
        wrapped = ObservedLifecycle(delegate, recorder)
        if (
            type(wrapped) is not _WRAPPER_TYPE
            or object.__getattribute__(wrapped, "_delegate") is not delegate
            or object.__getattribute__(wrapped, "_diagnostic") is not recorder
        ):
            return delegate
        if (
            diagnostics._slots is not slots
            or slots[index] is not False
            or diagnostics._misused is not False
        ):
            _mark_misused(diagnostics)
            return delegate
        slots[index] = recorder
        return wrapped
    except BaseException:
        return delegate
    finally:
        delegate = diagnostics = iteration = slots = recorder = wrapped = None


def _unknown_snapshot() -> dict[str, object]:
    return {
        "schema_version": 1,
        "available": False,
        "incomplete": True,
        "overflow": False,
        "state": "unavailable",
        "stages": None,
    }


def _snapshot_for_slot(slot: object) -> dict[str, object]:
    value = None
    try:
        if type(slot) is _RECORDER_TYPE:
            value = slot.snapshot()
            if _scalar_snapshot(value):
                return value
        return _unknown_snapshot()
    except BaseException:
        return _unknown_snapshot()
    finally:
        slot = value = None


def _snapshot_payload(
    diagnostics: ParentLifecycleDiagnostics | None, iteration: object
) -> dict[str, object]:
    slots = None
    try:
        payload = {
            "schema_version": 1,
            "current_iteration": iteration if _iteration(iteration) else None,
            "misused": None,
            "iterations": [_unknown_snapshot(), _unknown_snapshot()],
        }
        if type(diagnostics) is not _MANAGER_TYPE:
            return payload
        slots = diagnostics._slots
        if not _slots_valid(slots) or type(diagnostics._misused) is not bool:
            return payload
        payload["misused"] = diagnostics._misused
        if diagnostics._misused or not _iteration(iteration):
            return payload
        # Deliberately separate, nonblocking snapshots. No global epoch is claimed.
        payload["iterations"] = [_snapshot_for_slot(slots[0]), _snapshot_for_slot(slots[1])]
        return payload
    finally:
        diagnostics = iteration = slots = None


def _scalar_payload(value: object) -> bool:
    if type(value) is not dict or len(value) != len(_KEYS):
        return False
    keys = tuple(value)
    if any(type(key) is not str for key in keys) or keys != _KEYS:
        return False
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        return False
    current = value["current_iteration"]
    if current is not None and not _iteration(current):
        return False
    misuse = value["misused"]
    if misuse is not None and type(misuse) is not bool:
        return False
    rows = value["iterations"]
    return type(rows) is list and len(rows) == 2 and all(_scalar_snapshot(row) for row in rows)


def _fallback_line(iteration: object) -> str:
    try:
        current = (
            "1"
            if type(iteration) is int and iteration == 1
            else "2"
            if (type(iteration) is int and iteration == 2)
            else "null"
        )
        return (
            PREFIX
            + '{"schema_version":1,"current_iteration":'
            + current
            + ',"misused":null,"iterations":['
            + _UNKNOWN
            + ","
            + _UNKNOWN
            + "]}\n"
        )
    finally:
        iteration = None


def _release_metadata_traceback(
    error: BaseException, primary: BaseException | None, primary_traceback: object
) -> None:
    """Discard auxiliary history; restore the exact pending primary's entry traceback."""
    try:
        # The native descriptor bypasses custom exception attribute hooks. Auxiliary
        # history, including any preexisting traceback, is deliberately discarded.
        BaseException.__traceback__.__set__(error, primary_traceback if error is primary else None)
    except BaseException:
        pass
    finally:
        error = primary = primary_traceback = None


def emit_parent_failure_line(
    diagnostics: ParentLifecycleDiagnostics | None, *, iteration: object
) -> None:
    """One guarded dynamic stdout write, with a fallback only before I/O starts."""
    payload = text = decoded = line = None
    primary = primary_traceback = None
    primary_admitted = False
    try:
        primary = sys.exception()
        if primary is not None:
            primary_traceback = BaseException.__traceback__.__get__(primary)
        primary_admitted = True
        line = _fallback_line(iteration)
        try:
            payload = _snapshot_payload(diagnostics, iteration)
            if _scalar_payload(payload):
                text = json.dumps(
                    payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                )
                if (
                    type(text) is str
                    and text.isascii()
                    and not any(char in text for char in " \t\n\r")
                    and len(PREFIX) + len(text) + 1 <= LINE_CAP
                ):
                    decoded = json.loads(text)
                    if _scalar_payload(decoded) and decoded == payload:
                        line = PREFIX + text + "\n"
        except BaseException as error:
            # Keep the prebuilt fixed unknown line. No arbitrary values/errors print.
            if primary_admitted:
                _release_metadata_traceback(error, primary, primary_traceback)
        # A partial write is ambiguous; never retry or print a fallback after I/O.
        try:
            sys.stdout.write(line)
        except BaseException as error:
            if primary_admitted:
                _release_metadata_traceback(error, primary, primary_traceback)
    except BaseException as error:
        # A failure creating even the fixed fallback leaves output absent/unknown.
        if primary_admitted:
            _release_metadata_traceback(error, primary, primary_traceback)
    finally:
        diagnostics = iteration = payload = text = decoded = line = None
        primary = primary_traceback = None
