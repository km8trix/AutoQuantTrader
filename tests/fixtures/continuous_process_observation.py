"""Bounded, test-only metadata around the unchanged child observation call."""

import math
import subprocess
from collections.abc import Callable
from time import perf_counter_ns
from typing import Any

_COUNT_CAP = 4096
_ELAPSED_CAP_NS = 10**15
_CATEGORIES = ("returned", "TimeoutExpired", "ValueError", "OSError", "SubprocessError", "other")


class ChildObservationDiagnostic:
    """Keep fixed scalar counters and the first failure, including through cleanup."""

    def __init__(
        self,
        original: Callable[..., Any],
        *,
        clock_ns: Callable[[], int] = perf_counter_ns,
    ) -> None:
        self._original = original
        self._clock_ns = clock_ns
        self._calls = 0
        self._counts = dict.fromkeys(_CATEGORIES, 0)
        self._overflow = False
        self._first_failure: tuple[int, str, int | float | None, int] | None = None

    def observe(self, *args: Any, **kwargs: Any) -> Any:
        started = self._clock_ns()
        category = "returned"
        try:
            return self._original(*args, **kwargs)
        except subprocess.TimeoutExpired:
            category = "TimeoutExpired"
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
            elapsed = self._clock_ns() - started
            self._record(category, kwargs.get("timeout", 0.1), elapsed)

    def _record(self, category: str, timeout: object, elapsed: int) -> None:
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

    def summary(self, *, iteration: int) -> dict[str, object]:
        first = self._first_failure
        return {
            "iteration": iteration,
            "call_count": self._calls,
            "counts": dict(self._counts),
            "overflow": self._overflow,
            "first_failure": None
            if first is None
            else {
                "call": first[0],
                "category": first[1],
                "requested_timeout_seconds": first[2],
                "elapsed_ns": first[3],
            },
        }
