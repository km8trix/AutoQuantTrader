"""Failure-only scalar samples; no atomic epoch, phase history or outcome holder.

The caller supplies independently read post-return scalars. Missing output or an
unavailable field is unknown. This helper never imports a project class, probes a
business object or promises recovery from replaced primitives/resource exhaustion.
"""

from __future__ import annotations

import json
import sys

LINE_CAP = 4096
PREFIX = "AQT_PARENT_OUTCOME_DIAGNOSTIC "
SAMPLE_SCOPE = "post_return_independent"
FAULTS = ("stop", "ready_pid", "result", "early_release", "takeover")
STATUSES = ("completed", "failed", "stopped")
REASONS = (
    "child_failed",
    "child_observation_failed",
    "cleanup_incomplete",
    "completed",
    "deadline",
    "lease_lost",
    "lifecycle_incomplete",
    "lifecycle_invalid",
    "lifecycle_required",
    "memory_limit",
    "operation_busy",
    "output_limit",
    "probe_failed",
    "probe_stalled",
    "process_failed",
    "request_invalid",
    "stopped",
)
_KEYS = (
    "schema_version",
    "sample_scope",
    "available",
    "fault",
    "status",
    "reason",
    "stopped",
    "acted",
)
_UNKNOWN_LINE = (
    PREFIX + '{"schema_version":1,"sample_scope":"post_return_independent",'
    '"available":false,"fault":null,"status":null,"reason":null,'
    '"stopped":null,"acted":null}\n'
)


def _code(value: object, allowed: tuple[str, ...]) -> str | None:
    try:
        return value if type(value) is str and value in allowed else None
    finally:
        value = None


def _payload(
    *, fault: object, status: object, reason: object, stopped: object, acted: object
) -> dict[str, object]:
    try:
        clean_fault = _code(fault, FAULTS)
        clean_status = _code(status, STATUSES)
        clean_reason = _code(reason, REASONS)
        clean_stopped = stopped if type(stopped) is bool else None
        clean_acted = acted if type(acted) is bool else None
        return {
            "schema_version": 1,
            "sample_scope": SAMPLE_SCOPE,
            "available": all(
                value is not None
                for value in (clean_fault, clean_status, clean_reason, clean_stopped, clean_acted)
            ),
            "fault": clean_fault,
            "status": clean_status,
            "reason": clean_reason,
            "stopped": clean_stopped,
            "acted": clean_acted,
        }
    finally:
        fault = status = reason = stopped = acted = None


def _scalar_payload(value: object) -> bool:
    keys = item = None
    try:
        if type(value) is not dict or len(value) != len(_KEYS):
            return False
        keys = tuple(value)
        if any(type(key) is not str for key in keys) or keys != _KEYS:
            return False
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            return False
        if type(value["sample_scope"]) is not str or value["sample_scope"] != SAMPLE_SCOPE:
            return False
        if type(value["available"]) is not bool:
            return False
        for field, allowed in (("fault", FAULTS), ("status", STATUSES), ("reason", REASONS)):
            item = value[field]
            if item is not None and (type(item) is not str or item not in allowed):
                return False
        for field in ("stopped", "acted"):
            if value[field] is not None and type(value[field]) is not bool:
                return False
        return value["available"] is all(value[field] is not None for field in _KEYS[3:])
    finally:
        value = keys = item = None


def _strict_object_pairs(pairs: object) -> dict[str, object]:
    """Admit the complete raw object shape before JSON can collapse duplicate keys."""
    pair = key = value = keys = None
    try:
        if type(pairs) is not list or len(pairs) != len(_KEYS):
            raise ValueError("lifecycle outcome JSON object invalid")
        keys = []
        for pair in pairs:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("lifecycle outcome JSON object invalid")
            key, value = pair
            if type(key) is not str or (value is not None and type(value) not in (str, int, bool)):
                raise ValueError("lifecycle outcome JSON object invalid")
            keys.append(key)
        if tuple(keys) != _KEYS:
            raise ValueError("lifecycle outcome JSON object invalid")
        return dict(pairs)
    finally:
        pairs = pair = key = value = keys = None


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


def emit_lifecycle_outcome_failure(
    *, fault: object, status: object, reason: object, stopped: object, acted: object
) -> None:
    """One bounded dynamic stdout write; a partial write is never retried."""
    payload = text = decoded = line = None
    primary = primary_traceback = None
    primary_admitted = False
    try:
        primary = sys.exception()
        if primary is not None:
            primary_traceback = BaseException.__traceback__.__get__(primary)
        primary_admitted = True
        line = _UNKNOWN_LINE
        try:
            payload = _payload(
                fault=fault, status=status, reason=reason, stopped=stopped, acted=acted
            )
            if _scalar_payload(payload):
                text = json.dumps(
                    payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                )
                # Admit the complete serialized bound before invoking the decoder.
                if (
                    type(text) is str
                    and len(PREFIX) + len(text) + 1 <= LINE_CAP
                    and text.isascii()
                    and not any(char in text for char in " \t\n\r")
                ):
                    decoded = json.loads(text, object_pairs_hook=_strict_object_pairs)
                    if _scalar_payload(decoded) and decoded == payload:
                        line = PREFIX + text + "\n"
        except BaseException as error:
            if primary_admitted:
                _release_metadata_traceback(error, primary, primary_traceback)
        try:
            sys.stdout.write(line)
        except BaseException as error:
            if primary_admitted:
                _release_metadata_traceback(error, primary, primary_traceback)
    except BaseException as error:
        if primary_admitted:
            _release_metadata_traceback(error, primary, primary_traceback)
    finally:
        fault = status = reason = stopped = acted = payload = text = decoded = line = None
        primary = primary_traceback = None
