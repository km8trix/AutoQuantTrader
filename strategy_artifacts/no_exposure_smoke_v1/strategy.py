"""Deterministic no-exposure smoke strategy for the Phase 5C subprocess protocol.

This artifact intentionally depends only on the Python standard library.  It
accepts exactly one bounded canonical request on stdin and emits one canonical
response whose result contains no target or order authority.
"""

from __future__ import annotations

import json
import sys
from typing import NoReturn

PROTOCOL_VERSION = "phase5c-strategy-json-v1"
RESULT_CONTRACT_VERSION = "aqt-no-exposure-smoke-result-v1"
STRATEGY_ID = "no-exposure-smoke"
STRATEGY_VERSION = "1.0.0"
STRATEGY_CONFIGURATION_SHA256 = "064aebd6a8ea0ffea0300d36f3de7cab469d351029dbca03ab45c28561a74416"
MAX_REQUEST_BYTES = 1_048_576

_TOP_LEVEL_KEYS = {"invocation", "market_batch", "protocol_version"}
_INVOCATION_KEYS = {
    "control_scope_id",
    "environment",
    "id",
    "input_state_sha256",
    "market_batch_as_of",
    "market_batch_id",
    "market_batch_sha256",
    "requested_at",
    "runtime",
    "semantic_sha256",
    "strategy_configuration_sha256",
    "strategy_id",
    "strategy_version",
}
_RUNTIME_KEYS = {
    "artifact_sha256",
    "id",
    "launch_spec_sha256",
    "semantic_sha256",
    "version",
}


class _RequestError(ValueError):
    pass


def _fail() -> NoReturn:
    sys.stderr.write("no-exposure smoke request rejected\n")
    raise SystemExit(2)


def _reject_float(_value: str) -> object:
    raise _RequestError("floating-point numbers are unsupported")


def _reject_constant(_value: str) -> object:
    raise _RequestError("non-finite numbers are unsupported")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RequestError("duplicate JSON object key")
        result[key] = value
    return result


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _required_text(value: object) -> str:
    if type(value) is not str or not value:
        raise _RequestError("required text is absent")
    return value


def _decode_request(payload: bytes) -> tuple[dict[str, object], dict[str, object]]:
    try:
        decoded = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _RequestError, RecursionError) as error:
        raise _RequestError("invalid request") from error
    if type(decoded) is not dict or set(decoded) != _TOP_LEVEL_KEYS:
        raise _RequestError("unexpected request envelope")
    if _canonical_bytes(decoded) != payload:
        raise _RequestError("request is not canonical JSON")
    if decoded["protocol_version"] != PROTOCOL_VERSION:
        raise _RequestError("unsupported protocol")

    invocation = decoded["invocation"]
    market_batch = decoded["market_batch"]
    if type(invocation) is not dict or set(invocation) != _INVOCATION_KEYS:
        raise _RequestError("unexpected invocation")
    if type(market_batch) is not dict:
        raise _RequestError("unexpected market batch")
    runtime = invocation["runtime"]
    if type(runtime) is not dict or set(runtime) != _RUNTIME_KEYS:
        raise _RequestError("unexpected runtime binding")

    if len(sys.argv) != 3:
        raise _RequestError("verified artifact bootstrap is absent")
    if runtime["artifact_sha256"] != _required_text(sys.argv[2]):
        raise _RequestError("artifact identity mismatch")
    if invocation["strategy_id"] != STRATEGY_ID:
        raise _RequestError("strategy identity mismatch")
    if invocation["strategy_version"] != STRATEGY_VERSION:
        raise _RequestError("strategy version mismatch")
    if invocation["strategy_configuration_sha256"] != STRATEGY_CONFIGURATION_SHA256:
        raise _RequestError("strategy configuration mismatch")

    market_batch_id = _required_text(market_batch.get("id"))
    market_batch_sha256 = _required_text(market_batch.get("semantic_sha256"))
    if invocation["market_batch_id"] != market_batch_id:
        raise _RequestError("market batch identity mismatch")
    if invocation["market_batch_sha256"] != market_batch_sha256:
        raise _RequestError("market batch digest mismatch")
    _required_text(invocation["id"])
    _required_text(invocation["semantic_sha256"])
    return invocation, market_batch


def main() -> int:
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        _fail()
    try:
        invocation, market_batch = _decode_request(payload)
    except (OSError, _RequestError):
        _fail()

    result = {
        "contract_version": RESULT_CONTRACT_VERSION,
        "decision": "NO_EXPOSURE",
        "market_batch_id": market_batch["id"],
        "market_batch_sha256": market_batch["semantic_sha256"],
        "proposed_intents": [],
    }
    response = {
        "invocation_id": invocation["id"],
        "invocation_sha256": invocation["semantic_sha256"],
        "protocol_version": PROTOCOL_VERSION,
        "result": result,
    }
    sys.stdout.buffer.write(_canonical_bytes(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
