"""Opt-in diagnostic metadata for the existing synthetic retained restore test.

This helper records no arguments, locals, SQL, exception values or raw profiles.
It is test support, excluded from the application wheel and disabled by default.
"""

from __future__ import annotations

import cProfile
import heapq
import json
import os
import re
from pathlib import Path
from time import perf_counter_ns as _native_perf_counter_ns
from time import process_time_ns as _native_process_time_ns
from time import thread_time_ns as _native_thread_time_ns
from types import CodeType

_TOP_ENTRIES = 128
_MAX_ROWS = 4 * _TOP_ENTRIES
_MAX_REPORT_BYTES = 1_000_000
_CLOCK_CAP_NS = (1 << 63) - 1
_ELAPSED_CAP_NS = 10**15
_EXECUTE_TIMING_SCOPE = (
    "Native staggered whole factory.execute wall/process/thread intervals inside cProfile; "
    "clock and wrapper overhead included. Process CPU includes other process threads, "
    "not child processes; thread CPU covers the calling thread. Setup, construction, "
    "decoding, assertions, cleanup and report generation excluded. No subtraction, "
    "cause attribution, profitability or deadline-fit evidence."
)
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,199}\Z")
_PROJECT_DIRECTORIES = frozenset({"apps", "packages", "tests", "scripts", "migrations"})
_GENERATED_NAMES = frozenset(
    {"<module>", "<lambda>", "<genexpr>", "<listcomp>", "<dictcomp>", "<setcomp>"}
)


def _builtin_label(label: str) -> str:
    # cProfile builtin descriptions can contain object addresses. Only emit
    # recognized static identifier captures; never copy an unknown description.
    patterns = (
        r"<built-in method ([A-Za-z_][A-Za-z0-9_.]*)>",
        r"<built-in method ([A-Za-z_][A-Za-z0-9_.]*) of "
        r"[A-Za-z_][A-Za-z0-9_.]* object at 0x[0-9a-fA-F]+>",
        r"<method '([A-Za-z_][A-Za-z0-9_.]*)' of '([A-Za-z_][A-Za-z0-9_.]*)' objects>",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, label)
        if match is not None:
            return ".".join(reversed(match.groups()))[:200]
    return "<builtin>"


def _static_location(code: object, project: Path) -> tuple[str, str, int, str]:
    if type(code) is str:
        return "builtin", "<builtin>", 0, _builtin_label(code)
    if type(code) is not CodeType:
        return "unknown", "<unknown>", 0, "<unknown>"
    path = Path(code.co_filename)
    name = code.co_name
    if name not in _GENERATED_NAMES and _SAFE_NAME.fullmatch(name) is None:
        name = "<code>"
    if path.is_absolute() and path.is_relative_to(project):
        relative = path.relative_to(project)
        if (
            relative.parts
            and relative.parts[0] in _PROJECT_DIRECTORIES
            and len(relative.parts) <= 12
            and all(_SAFE_COMPONENT.fullmatch(part) for part in relative.parts)
        ):
            return "project", relative.as_posix(), code.co_firstlineno, name
    if "site-packages" in path.parts:
        relative_parts = path.parts[path.parts.index("site-packages") + 1 :]
        if (
            relative_parts
            and len(relative_parts) <= 12
            and all(_SAFE_COMPONENT.fullmatch(part) for part in relative_parts)
        ):
            return "dependency", "/".join(relative_parts), code.co_firstlineno, name
    if path.is_absolute() and _SAFE_COMPONENT.fullmatch(path.name):
        return "runtime", path.name, code.co_firstlineno, name
    return "generated", "<generated>", code.co_firstlineno, name


def _report(profiler, project: Path, *, execute_started: bool, execute_returned: bool) -> dict:
    stats = profiler.getstats()
    selected = {}
    for metric in ("totaltime", "inlinetime"):
        for project_only in (False, True):
            candidates = (
                (index, entry)
                for index, entry in enumerate(stats)
                if not project_only or _static_location(entry.code, project)[0] == "project"
            )
            for index, entry in heapq.nlargest(
                _TOP_ENTRIES, candidates, key=lambda pair: (getattr(pair[1], metric), -pair[0])
            ):
                selected[index] = entry
    if len(selected) > _MAX_ROWS:
        raise ValueError("RETAINED_PROFILE_ROW_BOUND")
    rows = []
    for index, entry in sorted(selected.items()):
        group, filename, line, name = _static_location(entry.code, project)
        rows.append(
            {
                "stats_entry_ordinal": index,
                "group": group,
                "file": filename,
                "line": line,
                "function": name,
                "calls": entry.callcount,
                "recursive_calls": entry.reccallcount,
                "inclusive_seconds": entry.totaltime,
                "self_seconds": entry.inlinetime,
            }
        )
    rows.sort(key=lambda row: row["inclusive_seconds"], reverse=True)
    return {
        "schema": "retained-factory-execute-static-cprofile/1",
        "diagnostic_only": True,
        "scope": (
            "Instrumented factory.execute only; fixture setup, factory construction, "
            "result decoding/assertions, cleanup and report generation are excluded. "
            "A returned execute call is not a passing restore test or startup acceptance."
        ),
        "factory_execute_started": execute_started,
        "factory_execute_returned": execute_returned,
        "stats_entries_considered": len(stats),
        "selection": (
            "Union of top128 inclusive and self-time entries, overall and project-only; "
            "up to512 rows. Unselected entries are omitted. Inclusive times overlap. "
            "Ordinals distinguish captured entries with identical static labels. "
            "These limits bound emitted data, not cProfile internal storage."
        ),
        "rows": rows,
    }


def _release_execute_clock_error(
    error, primary, traceback, cause, context, suppressed, *, restore_primary=True
):
    """Only a pending original operation error authorizes auxiliary fault isolation."""
    try:
        if error is not primary:
            BaseException.__traceback__.__set__(error, None)
            if BaseException.__context__.__get__(error) is primary:
                BaseException.__context__.__set__(error, None)
            if BaseException.__cause__.__get__(error) is primary:
                auxiliary_suppressed = BaseException.__suppress_context__.__get__(error)
                BaseException.__cause__.__set__(error, None)
                BaseException.__suppress_context__.__set__(error, auxiliary_suppressed)
        if restore_primary:
            BaseException.__traceback__.__set__(primary, traceback)
            BaseException.__cause__.__set__(primary, cause)
            BaseException.__context__.__set__(primary, context)
            BaseException.__suppress_context__.__set__(primary, suppressed)
    except BaseException:
        # Native cleanup faults cannot displace an already pending operation error.
        pass
    finally:
        error = primary = traceback = cause = context = suppressed = None


class RetainedRestoreProfile:
    def __init__(self, output: str, *, measure_execute: bool = False) -> None:
        if type(measure_execute) is not bool:
            raise TypeError("RETAINED_PROFILE_MEASURE_EXECUTE_BOOL")
        self._measure_execute = measure_execute
        self._wall_clock_ns = _native_perf_counter_ns if measure_execute else None
        self._process_clock_ns = _native_process_time_ns if measure_execute else None
        self._thread_clock_ns = _native_thread_time_ns if measure_execute else None
        self._timing_attempted = False
        self._timing_status = "unavailable"
        self._wall_elapsed_ns = None
        self._process_cpu_elapsed_ns = None
        self._thread_cpu_elapsed_ns = None
        self.output = Path(output)
        self.profiler = cProfile.Profile()
        self.execute_started = False
        self.execute_returned = False
        self.report_written = False
        self.profile_valid = False
        self.diagnostic_faults = []

    def execute(self, operation, **arguments):
        """Keep the original operation exception authoritative over profiler faults."""
        if self._measure_execute:
            return self._execute_measured(operation, arguments)
        try:
            self.profiler.enable()
        except BaseException:
            self.diagnostic_faults.append("enable_failed")
            # An enable error (including an original deadline/interrupt) remains
            # a failing diagnostic; the operation has not been attempted.
            raise
        self.execute_started = True
        try:
            result = operation(**arguments)
            self.execute_returned = True
            return result
        finally:
            try:
                self.profiler.disable()
            except BaseException:
                # This finally must not replace an in-flight operation error.
                # Even if a later disable succeeds, timings after this fault
                # cannot claim execute-only scope and will not be emitted.
                self.diagnostic_faults.append("execute_disable_failed")

    def _invalidate_execute_timing(self):
        self._timing_status = "invalid"
        self._wall_elapsed_ns = None
        self._process_cpu_elapsed_ns = None
        self._thread_cpu_elapsed_ns = None
        if "execute_timing_invalid" not in self.diagnostic_faults:
            self.diagnostic_faults.append("execute_timing_invalid")

    def _read_execute_clock(self, clock, primary):
        value = traceback = cause = context = suppressed = None
        try:
            if primary is not None:
                traceback = BaseException.__traceback__.__get__(primary)
                cause = BaseException.__cause__.__get__(primary)
                context = BaseException.__context__.__get__(primary)
                suppressed = BaseException.__suppress_context__.__get__(primary)
            value = clock()
            if type(value) is int and 0 <= value <= _CLOCK_CAP_NS:
                return value
            self._invalidate_execute_timing()
            return None
        except BaseException as error:
            self._invalidate_execute_timing()
            if primary is None:
                if type(error) is not OSError:
                    raise
                BaseException.__traceback__.__set__(error, None)
            else:
                _release_execute_clock_error(error, primary, traceback, cause, context, suppressed)
            return None
        finally:
            self = clock = primary = value = traceback = cause = context = suppressed = None

    def _sample_execute_clocks(self, primary):
        try:
            return (
                self._read_execute_clock(self._wall_clock_ns, primary),
                self._read_execute_clock(self._process_clock_ns, primary),
                self._read_execute_clock(self._thread_clock_ns, primary),
            )
        finally:
            self = primary = None

    def _finish_execute_timing(self, starts, ends):
        try:
            if self._timing_status == "invalid":
                return
            if any(value is None for value in starts + ends):
                self._invalidate_execute_timing()
                return
            deltas = tuple(end - start for start, end in zip(starts, ends, strict=True))
            if not all(0 <= value <= _ELAPSED_CAP_NS for value in deltas):
                self._invalidate_execute_timing()
                return
            self._wall_elapsed_ns, self._process_cpu_elapsed_ns, self._thread_cpu_elapsed_ns = (
                deltas
            )
            self._timing_status = "valid"
        finally:
            self = starts = ends = None

    def _finish_pending_execute_timing(self, starts, primary):
        """The complete end-metadata block is subordinate to an operation error."""
        traceback = cause = context = suppressed = ends = None
        snapshot_ready = False
        try:
            traceback = BaseException.__traceback__.__get__(primary)
            cause = BaseException.__cause__.__get__(primary)
            context = BaseException.__context__.__get__(primary)
            suppressed = BaseException.__suppress_context__.__get__(primary)
            snapshot_ready = True
            ends = self._sample_execute_clocks(primary)
            self._finish_execute_timing(starts, ends)
        except BaseException as error:
            self._invalidate_execute_timing()
            _release_execute_clock_error(
                error,
                primary,
                traceback,
                cause,
                context,
                suppressed,
                restore_primary=snapshot_ready,
            )
        finally:
            self = starts = primary = traceback = cause = context = suppressed = ends = None

    def _execute_measured(self, operation, arguments):
        starts = ends = result = None
        try:
            measure_this_call = not self._timing_attempted
            self._timing_attempted = True
            if not measure_this_call:
                self._invalidate_execute_timing()
            try:
                self.profiler.enable()
            except BaseException:
                self.diagnostic_faults.append("enable_failed")
                raise
            try:
                if measure_this_call:
                    try:
                        starts = self._sample_execute_clocks(None)
                    except BaseException:
                        self._invalidate_execute_timing()
                        raise
                self.execute_started = True
                try:
                    result = operation(**arguments)
                except BaseException as primary:
                    if measure_this_call:
                        self._finish_pending_execute_timing(starts, primary)
                    raise
                else:
                    self.execute_returned = True
                    if measure_this_call:
                        # A handled ambient exception is not an operation failure.
                        try:
                            ends = self._sample_execute_clocks(None)
                            self._finish_execute_timing(starts, ends)
                        except BaseException:
                            self._invalidate_execute_timing()
                            raise
                    return result
            finally:
                try:
                    self.profiler.disable()
                except BaseException:
                    self.diagnostic_faults.append("execute_disable_failed")
        finally:
            # New wrapper frames must not add error/argument/callback ownership.
            self = operation = arguments = starts = ends = result = None

    def _execute_timing_report(self):
        return {
            "status": self._timing_status,
            "wall_elapsed_ns": self._wall_elapsed_ns,
            "process_cpu_elapsed_ns": self._process_cpu_elapsed_ns,
            "thread_cpu_elapsed_ns": self._thread_cpu_elapsed_ns,
            "scope": _EXECUTE_TIMING_SCOPE,
        }

    def _invalid_report(self):
        return {
            "schema": "retained-factory-execute-static-cprofile/1",
            "diagnostic_only": True,
            "profile_status": "invalid",
            "scope": "Profiler control or report failed; no timing evidence is admitted.",
            "factory_execute_started": self.execute_started,
            "factory_execute_returned": self.execute_returned,
            "diagnostic_faults": list(self.diagnostic_faults),
            "stats_entries_considered": None,
            "rows": [],
        }

    def write_report(self) -> None:
        # No stdout/stderr output: broken output must not mask an original
        # assertion, restore or cleanup exception already propagating here.
        self.report_written = False
        self.profile_valid = False
        try:
            self.profiler.disable()
        except BaseException:
            self.diagnostic_faults.append("report_disable_failed")
        try:
            if self.diagnostic_faults:
                report = self._invalid_report()
            else:
                report = _report(
                    self.profiler,
                    Path(__file__).resolve().parents[1],
                    execute_started=self.execute_started,
                    execute_returned=self.execute_returned,
                )
                report["profile_status"] = "valid"
                report["diagnostic_faults"] = []
        except BaseException:
            self.diagnostic_faults.append("report_build_failed")
            report = self._invalid_report()
        descriptor = None
        try:
            if self._measure_execute:
                report["schema"] = "retained-factory-execute-static-cprofile/2"
                report["execute_timing"] = self._execute_timing_report()
            raw = (json.dumps(report, allow_nan=False, indent=2) + "\n").encode("utf-8")
            if len(raw) > _MAX_REPORT_BYTES:
                raise ValueError("RETAINED_PROFILE_BYTE_BOUND")
            descriptor = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(raw)
            self.report_written = True
            self.profile_valid = not self.diagnostic_faults
        except BaseException:
            self.diagnostic_faults.append("report_write_failed")
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException:
                    self.diagnostic_faults.append("report_descriptor_close_failed")
                    self.profile_valid = False
