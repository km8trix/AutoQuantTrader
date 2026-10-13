"""Temporary, default-off profile of iteration two's first parent observation.

The selected outer call includes the existing forwarding wrapper and its clocks.
Native cProfile seconds are instrumented timings, not thread CPU; inclusive rows
overlap. Row/output caps do not bound cProfile's internal storage or promise
lifetime transparency for dynamically replaced code/private constants. No GC,
SQL, cache, lease, freshness or financial policy is changed.
Initial profiler/trace/monitoring owners deny activation. The fixed original
delegate must not install/replace those owners during the call. A detected
takeover denies export/direct disable; native destruction/hook behavior after
such unsupported takeover is not a universal ownership-transparency claim.
"""

from __future__ import annotations

import heapq
import json
import math
import os
import stat
import sys
from _lsprof import profiler_entry as _NativeEntry
from cProfile import Profile as _NativeProfile
from pathlib import Path
from threading import Lock
from threading import get_ident as _native_get_ident
from types import CodeType

from tests.retained_restore_profile import (
    _GENERATED_NAMES,
    _PROJECT_DIRECTORIES,
    _SAFE_COMPONENT,
    _SAFE_NAME,
    _static_location,
)

_native_getprofile = sys.getprofile
_native_gettrace = sys.gettrace
_native_get_tool = sys.monitoring.get_tool
_native_get_events = sys.monitoring.get_events
TOP_ENTRIES = 128
ROW_CAP = 512
REPORT_CAP = 1_000_000
LINE_CAP = 4096
BOUNDED_TOP_ENTRIES = 32
BOUNDED_ROW_CAP = 128
BOUNDED_REPORT_CAP = 49152
BOUNDED_SCHEMA = "parent-probe-iteration2-first-observe-static-cprofile/2"
BOUNDED_SELECTION = (
    "Full native entry validation precedes the union of top32 inclusive and self-time "
    "entries overall and project-only, at most128 rows. Omitted rows are unknown; ordinals "
    "distinguish equal static labels. Output is at most49152 bytes; emitted limits do not "
    "bound native profiler storage, which retains code/stat entries until released."
)
PREFIX = "AQT_PARENT_FIRST_OBSERVE_PROFILE "
SCHEMA = "parent-probe-iteration2-first-observe-static-cprofile/1"
SCOPE = (
    "Successful native enable through native disable around the first iteration2 outer "
    "observe in the actual probe thread. Includes start-tail/finish-prefix bookkeeping, "
    "the existing forwarding dispatch/counters/native clocks, fresh delegate lookup/call, "
    "and disable boundary. Construction, scalar conversion, supervisor cleanup and file "
    "writing excluded. Conversion can delay queue publication outside measured intervals. "
    "Instrumented "
    "profiler timings are not thread CPU or removable costs; inclusive rows overlap. "
    "Automatic GC is not separately attributed. No cause or unprofiled deadline-fit evidence."
)
SELECTION = (
    "Union of top128 inclusive and self-time entries overall and project-only, at most512 "
    "rows. Omitted rows are unknown; ordinals distinguish equal static labels. Emitted limits "
    "do not bound native profiler storage, which retains code/stat entries until released."
)
_ROW_KEYS = (
    "stats_entry_ordinal",
    "group",
    "file",
    "line",
    "function",
    "calls",
    "recursive_calls",
    "inclusive_seconds",
    "self_seconds",
)
_REPORT_KEYS = (
    "schema",
    "diagnostic_only",
    "iteration",
    "observe_ordinal",
    "scope",
    "observe_started",
    "observe_returned",
    "stats_entries_considered",
    "selection",
    "rows",
)
_SCALAR_KEYS = ("schema_version", "selected", "active", "completed", "available", "report_written")


def _release_auxiliary(error, primary, traceback, cause, context, suppressed):
    """Only an explicitly pending original error authorizes fault isolation."""
    try:
        if error is not primary:
            BaseException.__traceback__.__set__(error, None)
            auxiliary_suppressed = BaseException.__suppress_context__.__get__(error)
            if BaseException.__cause__.__get__(error) is primary:
                BaseException.__cause__.__set__(error, None)
                BaseException.__suppress_context__.__set__(error, auxiliary_suppressed)
            if BaseException.__context__.__get__(error) is primary:
                BaseException.__context__.__set__(error, None)
        BaseException.__traceback__.__set__(primary, traceback)
        BaseException.__cause__.__set__(primary, cause)
        BaseException.__context__.__set__(primary, context)
        BaseException.__suppress_context__.__set__(primary, suppressed)
    except BaseException:
        # This guard is reachable only with an explicitly pending original error.
        # Native cleanup faults cannot acquire authority to replace that error.
        pass
    finally:
        error = primary = traceback = cause = context = suppressed = None


def _admit_report(report):
    if (
        type(report) is not dict
        or any(type(k) is not str for k in report)
        or tuple(report) != _REPORT_KEYS
    ):
        return False
    if (
        type(report["schema"]) is not str
        or report["schema"] != SCHEMA
        or report["diagnostic_only"] is not True
        or type(report["iteration"]) is not int
        or report["iteration"] != 2
        or type(report["observe_ordinal"]) is not int
        or report["observe_ordinal"] != 1
        or type(report["scope"]) is not str
        or report["scope"] != SCOPE
        or type(report["selection"]) is not str
        or report["selection"] != SELECTION
        or report["observe_started"] is not True
        or type(report["observe_returned"]) is not bool
        or type(report["stats_entries_considered"]) is not int
        or report["stats_entries_considered"] < 0
        or type(report["rows"]) is not list
        or len(report["rows"]) > ROW_CAP
    ):
        return False
    seen = set()
    for row in report["rows"]:
        if type(row) is not dict or any(type(k) is not str for k in row) or tuple(row) != _ROW_KEYS:
            return False
        ordinal = row["stats_entry_ordinal"]
        if type(ordinal) is not int or not 0 <= ordinal < report["stats_entries_considered"]:
            return False
        if ordinal in seen:
            return False
        seen.add(ordinal)
        if (
            type(row["group"]) is not str
            or row["group"]
            not in ("project", "dependency", "runtime", "generated", "unknown", "builtin")
            or type(row["file"]) is not str
            or not row["file"].isascii()
            or len(row["file"]) > 1211
            or row["file"].startswith("/")
            or type(row["function"]) is not str
            or not row["function"].isascii()
            or len(row["function"]) > 200
            or type(row["line"]) is not int
            or row["line"] < 0
            or type(row["calls"]) is not int
            or row["calls"] < 0
            or type(row["recursive_calls"]) is not int
            or not 0 <= row["recursive_calls"] <= row["calls"]
        ):
            return False
        for field in ("inclusive_seconds", "self_seconds"):
            value = row[field]
            if type(value) is not float or not math.isfinite(value) or value < 0:
                return False
        if row["self_seconds"] > row["inclusive_seconds"]:
            return False
        group, filename, name = row["group"], row["file"], row["function"]
        if (
            name not in _GENERATED_NAMES
            and name not in ("<code>", "<builtin>", "<unknown>")
            and _SAFE_NAME.fullmatch(name) is None
        ):
            return False
        if group in ("project", "dependency", "runtime"):
            parts = filename.split("/")
            if not 1 <= len(parts) <= 12 or any(
                _SAFE_COMPONENT.fullmatch(p) is None or p in (".", "..") for p in parts
            ):
                return False
            if group == "project" and parts[0] not in _PROJECT_DIRECTORIES:
                return False
            if group == "runtime" and len(parts) != 1:
                return False
        elif (
            filename
            != {"builtin": "<builtin>", "unknown": "<unknown>", "generated": "<generated>"}[group]
        ):
            return False
    return not any(
        a["inclusive_seconds"] < b["inclusive_seconds"]
        for a, b in zip(report["rows"], report["rows"][1:], strict=False)
    )


def create_first_observe_profile(*, enabled=False):
    """Exact False performs no helper construction or native profiling operation."""
    if type(enabled) is not bool:
        raise TypeError("PARENT_PROFILE_EXACT_BOOL")
    return FirstObserveProfile(enabled=True) if enabled else None


def wrap_first_observe_profile(delegate, *, profile, iteration):
    try:
        if profile is None:
            return delegate
        if type(profile) is not FirstObserveProfile:
            raise TypeError("PARENT_PROFILE_OWNER")
        return profile.wrap(delegate, iteration=iteration)
    finally:
        delegate = profile = iteration = None


def _static_report(stats, project, returned, *, _entry_type=_NativeEntry):
    entries = selected = rows = candidates = entry = code = values = report = raw = None
    group = filename = name = line = index = calls = recursive = total = own = None
    try:
        if type(stats) is not list:
            raise ValueError("PARENT_PROFILE_NATIVE_STATS")
        entries = []
        for index, entry in enumerate(stats):
            # The default captures the verified native type identity at definition;
            # module/name spellings or tuple-subclass shape cannot authenticate it.
            if type(entry) is not _entry_type or tuple.__len__(entry) != 6:
                raise ValueError("PARENT_PROFILE_NATIVE_STATS")
            values = tuple(tuple.__getitem__(entry, offset) for offset in range(5))
            code, calls, recursive, total, own = values
            if (
                (type(code) is not str and type(code) is not CodeType)
                or type(calls) is not int
                or calls < 0
                or type(recursive) is not int
                or not 0 <= recursive <= calls
                or type(total) is not float
                or not math.isfinite(total)
                or total < 0
                or type(own) is not float
                or not math.isfinite(own)
                or not 0 <= own <= total
            ):
                raise ValueError("PARENT_PROFILE_NATIVE_STATS")
            entries.append((index, code, calls, recursive, total, own))
        selected = {}
        for metric in (4, 5):
            for project_only in (False, True):
                candidates = (
                    (entry[0], entry)
                    for entry in entries
                    if not project_only or _static_location(entry[1], project)[0] == "project"
                )
                for index, entry in heapq.nlargest(
                    TOP_ENTRIES, candidates, key=lambda pair: (pair[1][metric], -pair[0])
                ):
                    selected[index] = entry
        if len(selected) > ROW_CAP:
            raise ValueError("PARENT_PROFILE_ROW_BOUND")
        rows = []
        for index, entry in sorted(selected.items()):
            group, filename, line, name = _static_location(entry[1], project)
            rows.append(
                dict(
                    zip(
                        _ROW_KEYS,
                        (
                            index,
                            group,
                            filename,
                            line,
                            name,
                            entry[2],
                            entry[3],
                            entry[4],
                            entry[5],
                        ),
                        strict=True,
                    )
                )
            )
        rows.sort(key=lambda row: row["inclusive_seconds"], reverse=True)
        report = dict(
            zip(
                _REPORT_KEYS,
                (
                    SCHEMA,
                    True,
                    2,
                    1,
                    SCOPE,
                    True,
                    returned,
                    len(stats),
                    SELECTION,
                    rows,
                ),
                strict=True,
            )
        )
        if not _admit_report(report):
            raise ValueError("PARENT_PROFILE_STATIC_DATA_INVALID")
        raw = (json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode(
            "utf-8"
        )
        if len(raw) > REPORT_CAP:
            raise ValueError("PARENT_PROFILE_OUTPUT_BOUND")
        return report
    finally:
        stats = project = returned = entries = selected = rows = candidates = entry = code = (
            values
        ) = report = raw = group = filename = name = line = index = calls = recursive = total = (
            own
        ) = None


def create_bounded_first_observe_profile(*, enabled=False):
    """Fixed Linux diagnostic route; no user-selected numeric or clock controls."""
    if type(enabled) is not bool:
        raise TypeError("PARENT_PROFILE_EXACT_BOOL")
    if not enabled:
        return None
    profile = FirstObserveProfile(enabled=True)
    profile._bounded = True
    return profile


def require_first_observe_output(output):
    """Present opt-in must name an exclusively owned private output directory."""
    if type(output) is not str or not os.path.isabs(output):
        raise TypeError("PARENT_PROFILE_OWNED_OUTPUT")
    directory, filename = os.path.split(output)
    if filename != "parent-probe-first-observe.json":
        raise ValueError("PARENT_PROFILE_OWNED_OUTPUT")
    parent = os.lstat(directory)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError("PARENT_PROFILE_OWNED_OUTPUT")
    # Never follow or overwrite a previously created output, including a symlink.
    try:
        os.lstat(output)
    except FileNotFoundError:
        return output
    raise ValueError("PARENT_PROFILE_OWNED_OUTPUT")


def _admit_bounded_report(report):
    legacy = None
    try:
        if (
            type(report) is not dict
            or any(type(key) is not str for key in report)
            or tuple(report) != _REPORT_KEYS
            or type(report["schema"]) is not str
            or report["schema"] != BOUNDED_SCHEMA
            or type(report["selection"]) is not str
            or report["selection"] != BOUNDED_SELECTION
            or type(report["rows"]) is not list
            or len(report["rows"]) > BOUNDED_ROW_CAP
        ):
            return False
        legacy = report.copy()
        legacy["schema"], legacy["selection"] = SCHEMA, SELECTION
        return _admit_report(legacy)
    finally:
        report = legacy = None


def _bounded_static_report(stats, project, returned):
    """Legacy projection validates every raw entry before this smaller selection.

    Every top32 set is contained in the already admitted top128 union. The
    intermediate legacy report retains its original1MB cap; this fixed route
    admits only128 rows and49152 bytes, with no raw entry or code crossing threads.
    """
    legacy = selected = candidates = report = raw = row = None
    try:
        legacy = _static_report(stats, project, returned)
        if not _admit_report(legacy):
            raise ValueError("PARENT_PROFILE_STATIC_DATA_INVALID")
        selected = {}
        for metric in ("inclusive_seconds", "self_seconds"):
            for project_only in (False, True):
                candidates = (
                    row for row in legacy["rows"] if not project_only or row["group"] == "project"
                )
                for row in heapq.nlargest(
                    BOUNDED_TOP_ENTRIES,
                    candidates,
                    key=lambda item: (item[metric], -item["stats_entry_ordinal"]),
                ):
                    selected[row["stats_entry_ordinal"]] = row
        report = legacy.copy()
        report["schema"], report["selection"] = BOUNDED_SCHEMA, BOUNDED_SELECTION
        report["rows"] = [row for index, row in sorted(selected.items())]
        report["rows"].sort(key=lambda item: item["inclusive_seconds"], reverse=True)
        if not _admit_bounded_report(report):
            raise ValueError("PARENT_PROFILE_STATIC_DATA_INVALID")
        raw = (json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode(
            "utf-8"
        )
        if len(raw) > BOUNDED_REPORT_CAP:
            raise ValueError("PARENT_PROFILE_OUTPUT_BOUND")
        return report
    finally:
        stats = project = returned = legacy = selected = candidates = report = raw = row = None


class FirstObserveProfile:
    """Fixed native owners; one claim; stopped scalar data only crosses threads."""

    __slots__ = (
        "_bounded",
        "_clear",
        "_disable",
        "_enabled",
        "_factory",
        "_get_events",
        "_get_ident",
        "_get_tool",
        "_getprofile",
        "_getstats",
        "_gettrace",
        "_lock",
        "_monitoring",
        "_owner",
        "_phase",
        "_profile_marker",
        "_profile_type",
        "_profiler",
        "_project",
        "_report",
    )

    def __init__(self, *, enabled=False):
        if type(enabled) is not bool:
            raise TypeError("PARENT_PROFILE_EXACT_BOOL")
        self._enabled = enabled
        self._bounded = False
        self._lock = Lock()
        self._phase = "unselected"
        self._report = self._profiler = self._disable = self._getstats = self._clear = None
        self._owner = None
        self._profile_marker = self._monitoring = None
        self._factory = self._profile_type = _NativeProfile
        self._getprofile, self._gettrace = _native_getprofile, _native_gettrace
        self._get_tool, self._get_events = _native_get_tool, _native_get_events
        self._get_ident = _native_get_ident
        self._project = Path(__file__).resolve().parents[2]

    def wrap(self, delegate, *, iteration):
        try:
            if not self._enabled:
                return delegate
            if type(iteration) is not int or iteration not in (1, 2):
                raise TypeError("PARENT_PROFILE_ITERATION")
            return _ProfiledLifecycle(delegate, self) if iteration == 2 else delegate
        finally:
            self = delegate = iteration = None

    def _claim(self):
        if not self._enabled:
            return False
        if not self._lock.acquire(blocking=False):
            # Consume this actual first call rather than silently profile a later
            # ordinal. This sticky scalar assignment does not wait on the lock.
            if self._phase == "unselected":
                self._phase = "invalid"
            return False
        try:
            if self._phase != "unselected":
                return False
            self._phase = "active"
            return True
        finally:
            self._lock.release()

    def _start(self):
        profiler = enable = None
        try:
            self._owner = self._get_ident()
            if type(self._owner) is not int or not 0 <= self._owner <= (1 << 63) - 1:
                raise ValueError("PARENT_PROFILE_NATIVE_THREAD")
            if self._getprofile() is not None or self._gettrace() is not None:
                self._phase = "blocked"
                return False
            if any(name is not None or events != 0 for name, events in self._monitoring_state()):
                self._phase = "blocked"
                return False
            profiler = self._factory()
            if type(profiler) is not self._profile_type:
                raise TypeError("PARENT_PROFILE_NATIVE_OWNER")
            self._profiler = profiler
            enable, self._disable, self._getstats, self._clear = (
                profiler.enable,
                profiler.disable,
                profiler.getstats,
                profiler.clear,
            )
            enable()
            self._profile_marker = self._getprofile()
            if self._profile_marker is not None and self._profile_marker is not profiler:
                raise RuntimeError("PARENT_PROFILE_OWNER_CHANGED")
            self._monitoring = self._monitoring_state()
            return True
        except BaseException as primary:
            # A possibly partially enabled native profiler is stopped by this same
            # probe thread. Only this explicit pending enable error can isolate a
            # second cleanup error; no ambient exception grants that authority.
            self._finish(primary, returned=False, started=False)
            raise
        finally:
            self = profiler = enable = None

    def _monitoring_state(self):
        rows = []
        for tool in range(6):
            name, events = self._get_tool(tool), self._get_events(tool)
            if (
                (name is not None and type(name) is not str)
                or type(events) is not int
                or not 0 <= events <= (1 << 63) - 1
            ):
                raise ValueError("PARENT_PROFILE_NATIVE_MONITORING")
            rows.append((name, events))
        return tuple(rows)

    def _finish(self, primary, *, returned, started=True):
        stats = report = traceback = cause = context = suppressed = marker = identity = None
        ready = owner_matches = published = False
        try:
            if primary is not None:
                traceback = BaseException.__traceback__.__get__(primary)
                cause = BaseException.__cause__.__get__(primary)
                context = BaseException.__context__.__get__(primary)
                suppressed = BaseException.__suppress_context__.__get__(primary)
                ready = True
            identity = self._get_ident()
            if (
                type(self._owner) is not int
                or not 0 <= self._owner <= (1 << 63) - 1
                or type(identity) is not int
                or not 0 <= identity <= (1 << 63) - 1
            ):
                raise ValueError("PARENT_PROFILE_NATIVE_THREAD")
            owner_matches = self._owner == identity
            if not owner_matches:
                raise RuntimeError("PARENT_PROFILE_WRONG_THREAD")
            if self._disable is None:
                return
            marker = self._getprofile()
            if (
                (marker is not None and marker is not self._profiler)
                or self._gettrace() is not None
                or (
                    started
                    and (
                        marker is not self._profile_marker
                        or self._monitoring_state() != self._monitoring
                    )
                )
            ):
                # The fixed Source contract excludes takeover. Never export this
                # invalid interval or explicitly disable a detected new owner.
                return
            self._disable()
            if not started:
                return
            stats = self._getstats()
            if self._bounded:
                report = _bounded_static_report(stats, self._project, returned)
            else:
                report = _static_report(stats, self._project, returned)
            self._clear()
            # Raw owners are released in this thread before stopped scalar data
            # becomes eligible for a main-thread write.
            stats = None
            self._profiler = self._disable = self._getstats = self._clear = None
            if self._lock.acquire(blocking=False):
                try:
                    self._report = report
                    self._phase = "valid"
                    published = True
                finally:
                    self._lock.release()
        except BaseException as error:
            self._report = None
            if primary is None:
                raise
            if ready:
                _release_auxiliary(error, primary, traceback, cause, context, suppressed)
        finally:
            if owner_matches:
                if not published:
                    self._phase = "invalid"
                # Never hand raw profiler, bound methods, stats, code, frames or
                # arguments to the main-thread writer, including failure paths.
                self._profiler = self._disable = self._getstats = self._clear = None
                self._owner = None
                self._profile_marker = self._monitoring = None
            self = primary = stats = report = traceback = cause = context = suppressed = marker = (
                identity
            ) = None

    def availability(self):
        if not self._enabled:
            return None
        if not self._lock.acquire(blocking=False):
            # These false flags are unknown when available is false, not evidence
            # that the callback did not enter or is no longer active.
            return dict(zip(_SCALAR_KEYS, (1, False, False, False, False, False), strict=True))
        try:
            phase = self._phase
            return dict(
                zip(
                    _SCALAR_KEYS,
                    (
                        1,
                        phase != "unselected",
                        phase == "active",
                        phase in ("invalid", "blocked", "valid", "writing", "written"),
                        phase in ("valid", "written"),
                        phase == "written",
                    ),
                    strict=True,
                )
            )
        finally:
            self._lock.release()

    def write_after_cleanup(self, output, *, primary=None):
        """Never wait, touch active stats, disable another thread or replay a call."""
        report = raw = descriptor = traceback = cause = context = suppressed = None
        ready = False
        try:
            if primary is not None:
                traceback = BaseException.__traceback__.__get__(primary)
                cause = BaseException.__cause__.__get__(primary)
                context = BaseException.__context__.__get__(primary)
                suppressed = BaseException.__suppress_context__.__get__(primary)
                ready = True
            if not self._enabled or not self._lock.acquire(blocking=False):
                return False
            try:
                if self._phase != "valid":
                    return False
                report = self._report
                self._phase = "writing"
            finally:
                self._lock.release()
            if self._bounded:
                if not _admit_bounded_report(report):
                    raise ValueError("PARENT_PROFILE_STATIC_DATA_INVALID")
            elif not _admit_report(report):
                raise ValueError("PARENT_PROFILE_STATIC_DATA_INVALID")
            raw = (json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode(
                "utf-8"
            )
            if len(raw) > (BOUNDED_REPORT_CAP if self._bounded else REPORT_CAP):
                raise ValueError("PARENT_PROFILE_OUTPUT_BOUND")
            if type(output) is not str or not os.path.isabs(output):
                raise TypeError("PARENT_PROFILE_OWNED_OUTPUT")
            directory, filename = os.path.split(output)
            if filename != "parent-probe-first-observe.json":
                raise ValueError("PARENT_PROFILE_OWNED_OUTPUT")
            parent = os.lstat(directory)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid()
                or parent.st_mode & 0o077
            ):
                raise ValueError("PARENT_PROFILE_OWNED_OUTPUT")
            descriptor = os.open(
                output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                if stream.write(raw) != len(raw):
                    raise OSError("PARENT_PROFILE_SHORT_WRITE")
            self._phase = "written"
            return True
        except BaseException as error:
            if self._phase == "writing":
                self._phase = "invalid"
            if primary is None:
                raise
            if ready:
                _release_auxiliary(error, primary, traceback, cause, context, suppressed)
            return False
        finally:
            try:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if primary is None:
                            raise
                        if ready:
                            _release_auxiliary(
                                error, primary, traceback, cause, context, suppressed
                            )
            finally:
                self = output = primary = report = raw = descriptor = traceback = cause = (
                    context
                ) = suppressed = None

    def emit_availability(self, *, primary=None):
        value = text = traceback = cause = context = suppressed = None
        ready = False
        try:
            if primary is not None:
                traceback = BaseException.__traceback__.__get__(primary)
                cause = BaseException.__cause__.__get__(primary)
                context = BaseException.__context__.__get__(primary)
                suppressed = BaseException.__suppress_context__.__get__(primary)
                ready = True
            value = self.availability()
            if value is None:
                return
            if (
                type(value) is not dict
                or any(type(k) is not str for k in value)
                or tuple(value) != _SCALAR_KEYS
            ):
                raise ValueError("PARENT_PROFILE_SCALAR_DATA_INVALID")
            if (
                type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or any(type(value[k]) is not bool for k in _SCALAR_KEYS[1:])
            ):
                raise ValueError("PARENT_PROFILE_SCALAR_DATA_INVALID")
            if (
                (not value["selected"] and any(value[k] for k in _SCALAR_KEYS[2:]))
                or (
                    value["active"]
                    and (value["completed"] or value["available"] or value["report_written"])
                )
                or (value["available"] and (not value["completed"] or not value["selected"]))
                or (value["report_written"] and not value["available"])
            ):
                raise ValueError("PARENT_PROFILE_SCALAR_DATA_INVALID")
            text = (
                PREFIX
                + json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
                + "\n"
            )
            if not text.isascii() or len(text) > LINE_CAP:
                raise ValueError("PARENT_PROFILE_LINE_BOUND")
            sys.stdout.write(text)
        except BaseException as error:
            if primary is None:
                raise
            if ready:
                _release_auxiliary(error, primary, traceback, cause, context, suppressed)
        finally:
            self = primary = value = text = traceback = cause = context = suppressed = None


class _ProfiledLifecycle:
    __slots__ = ("__weakref__", "_delegate", "_profile")

    def __init__(self, delegate, profile):
        self._delegate, self._profile = delegate, profile

    def prepare(self, startup):
        try:
            return self._delegate.prepare(startup)
        finally:
            self = startup = None

    def require_result(self, payload):
        try:
            return self._delegate.require_result(payload)
        finally:
            self = payload = None

    def observe(self, *, child_pid, child_exited):
        delegate = profile = result = None
        selected = started = False
        try:
            delegate, profile = self._delegate, self._profile
            selected = profile._claim()
            if not selected:
                return delegate.observe(child_pid=child_pid, child_exited=child_exited)
            started = profile._start()
            try:
                # No callee lookup is hoisted: the existing inner wrapper retains
                # its original dynamic SQL-probe lookup inside its timed interval.
                result = delegate.observe(child_pid=child_pid, child_exited=child_exited)
            except BaseException as primary:
                if started:
                    profile._finish(primary, returned=False)
                raise
            else:
                if started:
                    profile._finish(None, returned=True)
                return result
        finally:
            self = delegate = profile = result = child_pid = child_exited = None
