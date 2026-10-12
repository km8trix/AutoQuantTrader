"""Bounded, test-only metadata around the unchanged child observation call."""

import math
import subprocess
import sys
from collections.abc import Callable
from time import perf_counter_ns
from time import thread_time_ns as _native_thread_time_ns
from types import CodeType
from typing import Any

_COUNT_CAP = 4096
_ELAPSED_CAP_NS = 10**15
_CPU_CLOCK_CAP_NS = (1 << 63) - 1
_TRACEBACK_CAP = 8
_CONSTANT_CAP = 32
_LINE_OFFSET_CAP = 4095
_CATEGORIES = ("returned", "TimeoutExpired", "ValueError", "OSError", "SubprocessError", "other")


def _release_thread_clock_error(
    error: BaseException, primary: BaseException | None, primary_traceback: object
) -> None:
    """Discard clock-fault history without adding ownership of the pending primary."""
    try:
        BaseException.__traceback__.__set__(error, primary_traceback if error is primary else None)
        if error is not primary and primary is not None:
            if BaseException.__context__.__get__(error) is primary:
                BaseException.__context__.__set__(error, None)
            if BaseException.__cause__.__get__(error) is primary:
                suppressed = BaseException.__suppress_context__.__get__(error)
                BaseException.__cause__.__set__(error, None)
                BaseException.__suppress_context__.__set__(error, suppressed)
    except BaseException:
        pass
    finally:
        error = primary = primary_traceback = None


class ChildObservationDiagnostic:
    """Keep fixed scalar counters and the first failure, including through cleanup."""

    def __init__(
        self,
        original: Callable[..., Any],
        *,
        clock_ns: Callable[[], int] = perf_counter_ns,
        deadline_code: CodeType | None = None,
        thread_clock_ns: Callable[[], int] | None = None,
    ) -> None:
        self._original = original
        self._clock_ns = clock_ns
        self._calls = 0
        self._counts = dict.fromkeys(_CATEGORIES, 0)
        self._overflow = False
        self._first_failure: tuple[int, str, int | float | None, int] | None = None
        # Only the native clock marker enables sampling; foreign values are not stored or called.
        self._thread_cpu_enabled = thread_clock_ns is not None
        self._thread_cpu_admitted = thread_clock_ns is _native_thread_time_ns
        self._thread_cpu_clock = _native_thread_time_ns if self._thread_cpu_admitted else None
        self._first_thread_cpu_elapsed_ns: int | None = None
        if self._thread_cpu_enabled and not self._thread_cpu_admitted:
            self._overflow = True
        self._first_timeout_site: int | None = None
        self._deadline_code: CodeType | None = None
        self._deadline_check_code: CodeType | None = None
        if deadline_code is not None:
            try:
                self._bind_deadline_code(deadline_code)
            except BaseException:
                # Optional metadata must not prevent the original observation.
                self._deadline_code = None
                self._deadline_check_code = None
                self._overflow = True

    def _bind_deadline_code(self, code: CodeType) -> None:
        if type(code) is not CodeType or len(code.co_consts) > _CONSTANT_CAP:
            self._overflow = True
            return
        check: CodeType | None = None
        for constant in code.co_consts:
            if type(constant) is CodeType and constant.co_name == "require_time":
                if check is not None:
                    self._overflow = True
                    return
                check = constant
        if check is None:
            self._overflow = True
            return
        # Code identities are static metadata, not callable/global/frame owners.
        self._deadline_code = code
        self._deadline_check_code = check

    def _timeout_check_offset(self, error: BaseException) -> int | None:
        if (
            type(error) is not subprocess.TimeoutExpired
            or self._deadline_code is None
            or self._deadline_check_code is None
        ):
            return None
        traceback = error.__traceback__
        previous_code: CodeType | None = None
        previous_offset: int | None = None
        found: int | None = None
        depth = 0
        while traceback is not None and depth < _TRACEBACK_CAP:
            code = traceback.tb_frame.f_code
            if code is self._deadline_check_code and previous_code is self._deadline_code:
                if (
                    found is not None
                    or previous_offset is None
                    or not 0 <= previous_offset <= _LINE_OFFSET_CAP
                ):
                    self._overflow = True
                    return None
                found = previous_offset
            previous_code = code
            previous_offset = (
                traceback.tb_lineno - code.co_firstlineno if code is self._deadline_code else None
            )
            traceback = traceback.tb_next
            depth += 1
        if traceback is not None:
            self._overflow = True
            return None
        # Exhaust the bounded scan: an early match cannot hide extra frames.
        return found

    def observe(self, *args: Any, **kwargs: Any) -> Any:
        thread_started = self._sample_thread_cpu() if self._thread_cpu_admitted else None
        started = self._clock_ns()
        category = "returned"
        timeout_error: BaseException | None = None
        try:
            return self._original(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            category = "TimeoutExpired"
            timeout_error = error
            raise
        except ValueError:
            category = "ValueError"
            raise
        except OSError:
            category = "OSError"
            raise
        except subprocess.SubprocessError:
            category = "SubprocessError"
            raise
        except BaseException:
            category = "other"
            raise
        finally:
            try:
                elapsed = self._clock_ns() - started
                thread_elapsed: int | None = None
                if self._thread_cpu_admitted:
                    thread_finished = self._sample_thread_cpu()
                    if (
                        thread_started is not None
                        and thread_finished is not None
                        and 0 <= thread_finished - thread_started <= _ELAPSED_CAP_NS
                    ):
                        thread_elapsed = thread_finished - thread_started
                    else:
                        self._overflow = True
                if (
                    self._thread_cpu_enabled
                    and category != "returned"
                    and self._first_failure is None
                ):
                    self._first_thread_cpu_elapsed_ns = thread_elapsed
                timeout_site: int | None = None
                if timeout_error is not None and self._first_failure is None:
                    try:
                        timeout_site = self._timeout_check_offset(timeout_error)
                    except BaseException:
                        self._overflow = True
                self._record(category, kwargs.get("timeout", 0.1), elapsed, timeout_site)
            finally:
                # The propagated traceback includes this frame. Leaving the
                # error here would add an exception/frame/payload retention cycle.
                timeout_error = None

    def _sample_thread_cpu(self) -> int | None:
        """Bound native metadata only; faults cannot replace the original observation."""
        value = primary = primary_traceback = None
        primary_admitted = False
        try:
            primary = sys.exception()
            if primary is not None:
                primary_traceback = BaseException.__traceback__.__get__(primary)
            primary_admitted = True
            value = self._thread_cpu_clock()
            if type(value) is int and 0 <= value <= _CPU_CLOCK_CAP_NS:
                return value
            self._overflow = True
            return None
        except BaseException as error:
            if primary_admitted:
                _release_thread_clock_error(error, primary, primary_traceback)
            self._overflow = True
            return None
        finally:
            self = value = primary = primary_traceback = None

    def _record(
        self, category: str, timeout: object, elapsed: int, timeout_site: int | None = None
    ) -> None:
        if self._calls == _COUNT_CAP or self._counts[category] == _COUNT_CAP:
            self._overflow = True
        self._calls = min(_COUNT_CAP, self._calls + 1)
        self._counts[category] = min(_COUNT_CAP, self._counts[category] + 1)
        if category == "returned" or self._first_failure is not None:
            return
        requested: int | float | None = None
        if (
            (type(timeout) is int or type(timeout) is float)
            and 0 <= timeout <= 120
            and math.isfinite(timeout)
        ):
            requested = timeout
        else:
            self._overflow = True
        if not 0 <= elapsed <= _ELAPSED_CAP_NS:
            self._overflow = True
        self._first_failure = (
            self._calls,
            category,
            requested,
            min(_ELAPSED_CAP_NS, max(0, elapsed)),
        )
        self._first_timeout_site = timeout_site

    def summary(self, *, iteration: int) -> dict[str, object]:
        first = self._first_failure
        first_summary = (
            None
            if first is None
            else {
                "call": first[0],
                "category": first[1],
                "requested_timeout_seconds": first[2],
                "elapsed_ns": first[3],
            }
        )
        if first_summary is not None and self._first_timeout_site is not None:
            first_summary["deadline_check_line_offset"] = self._first_timeout_site
        if first_summary is not None and self._thread_cpu_enabled:
            first_summary["thread_cpu_elapsed_ns"] = self._first_thread_cpu_elapsed_ns
        return {
            "iteration": iteration,
            "call_count": self._calls,
            "counts": dict(self._counts),
            "overflow": self._overflow,
            "first_failure": first_summary,
        }
