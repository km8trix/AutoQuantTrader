"""Standalone stdlib-only Phase 3H economic child.

The parent snapshots these reviewed bytes behind an unlinked read-only file
descriptor and launches ``python -I -S -B /dev/fd/<fixed-fd>``.  This program
must not import project code, load a fixture, accept an argv path, or perform
network or filesystem I/O.  All failures use one nonzero exit and emit no
diagnostic text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import sys
from decimal import (
    Clamped,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)

CONTRACT_VERSION = "phase3h-fixture-economic-segment-v1"
MODEL_VERSION = "immediate-causal-close-zero-cost-v1"
MAX_REQUEST_BYTES = 262_144
MAX_ROWS = 2_048
MAX_INSTRUMENTS = 64
CPU_SECONDS = 2
ADDRESS_SPACE_LIMITS = {
    "darwin": 1_099_511_627_776,
    "linux": 536_870_912,
}
OPEN_FILES = 16
FILE_BYTES = 0
CHILD_PROCESSES = 0
EXPECTED_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONUTF8": "1",
    "TZ": "UTC",
    "__CF_USER_TEXT_ENCODING": "0x0:0x0:0x0",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(?:0|-?[1-9][0-9]*e-?[0-9]+)$")
_EXACT_CONTEXT = Context(
    prec=64,
    Emin=-63,
    Emax=63,
    clamp=0,
    flags=[],
    traps=[
        Clamped,
        DivisionByZero,
        FloatOperation,
        Inexact,
        InvalidOperation,
        Overflow,
        Rounded,
        Subnormal,
        Underflow,
    ],
)


class _ProtocolError(ValueError):
    pass


def _plain_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _ProtocolError("duplicate")
        value[key] = item
    return value


def _reject_number(_value: str) -> None:
    raise _ProtocolError("float")


def _decimal(value: object) -> Decimal:
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise _ProtocolError("decimal")
    parsed = Decimal(value)
    if not parsed.is_finite() or _decimal_text(parsed) != value:
        raise _ProtocolError("decimal")
    _, digits, raw_exponent = parsed.as_tuple()
    if any(digits):
        exponent = int(raw_exponent)
        if exponent < -10 or len(digits) + exponent - 1 >= 18:
            raise _ProtocolError("decimal")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if type(value) is not Decimal or not value.is_finite():
        raise _ProtocolError("decimal")
    sign, raw_digits, raw_exponent = value.as_tuple()
    if not any(raw_digits):
        return "0"
    digits = list(raw_digits)
    exponent = int(raw_exponent)
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    coefficient = "".join(str(digit) for digit in digits)
    return f"{'-' if sign else ''}{coefficient}e{exponent}"


def _add(left: Decimal, right: Decimal) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            return left + right
    except DecimalException as error:
        raise _ProtocolError("arithmetic") from error


def _subtract(left: Decimal, right: Decimal) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            return left - right
    except DecimalException as error:
        raise _ProtocolError("arithmetic") from error


def _multiply(left: Decimal, right: Decimal) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            return left * right
    except DecimalException as error:
        raise _ProtocolError("arithmetic") from error


def _require_digest(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _ProtocolError("digest")
    return value


def _require_text(value: object, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise _ProtocolError("text")
    return value


def _apply_resource_limits() -> dict[str, int]:
    try:
        address_space_bytes = ADDRESS_SPACE_LIMITS[sys.platform]
    except KeyError as error:
        raise _ProtocolError("platform") from error
    limits = (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, CPU_SECONDS),
        (resource.RLIMIT_AS, address_space_bytes),
        (resource.RLIMIT_NOFILE, OPEN_FILES),
        (resource.RLIMIT_FSIZE, FILE_BYTES),
        (resource.RLIMIT_NPROC, CHILD_PROCESSES),
    )
    for kind, value in limits:
        resource.setrlimit(kind, (value, value))
        if resource.getrlimit(kind) != (value, value):
            raise _ProtocolError("resource-limit")
    return {
        "address_space_bytes": address_space_bytes,
        "child_processes": CHILD_PROCESSES,
        "core_bytes": 0,
        "cpu_seconds": CPU_SECONDS,
        "file_bytes": FILE_BYTES,
        "open_files": OPEN_FILES,
    }


def _decode_request(encoded: bytes) -> tuple[dict[str, object], str]:
    try:
        text = encoded.decode("utf-8", errors="strict")
        envelope = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise _ProtocolError("json") from error
    if _plain_json_bytes(envelope) != encoded:
        raise _ProtocolError("canonical")
    if type(envelope) is not dict or set(envelope) != {
        "contract_version",
        "request",
        "request_payload_sha256",
    }:
        raise _ProtocolError("envelope")
    if envelope["contract_version"] != CONTRACT_VERSION:
        raise _ProtocolError("version")
    request = envelope["request"]
    if type(request) is not dict:
        raise _ProtocolError("request")
    payload_sha256 = _require_digest(envelope["request_payload_sha256"])
    if hashlib.sha256(_plain_json_bytes(request)).hexdigest() != payload_sha256:
        raise _ProtocolError("payload")
    expected = {
        "attempt_id",
        "completion_receipt_sha256",
        "configuration_sha256",
        "family_id",
        "job_id",
        "model_version",
        "request_semantic_sha256",
        "rows",
        "segment_kind",
        "segment_sha256",
        "starting_cash",
        "target_artifact_sha256",
        "target_certification_sha256",
        "target_transcript_sha256",
    }
    if set(request) != expected or request["model_version"] != MODEL_VERSION:
        raise _ProtocolError("request")
    for key in (
        "attempt_id",
        "completion_receipt_sha256",
        "configuration_sha256",
        "family_id",
        "job_id",
        "request_semantic_sha256",
        "segment_sha256",
        "target_artifact_sha256",
        "target_certification_sha256",
        "target_transcript_sha256",
    ):
        _require_digest(request[key])
    if request["segment_kind"] not in {"train", "validation", "test"}:
        raise _ProtocolError("segment")
    if request["starting_cash"] != "1e5":
        raise _ProtocolError("cash")
    return request, payload_sha256


def _evaluate(request: dict[str, object]) -> dict[str, object]:
    rows = request["rows"]
    if type(rows) is not list or not 0 < len(rows) <= MAX_ROWS:
        raise _ProtocolError("rows")
    quantities: dict[str, Decimal] = {}
    symbols: dict[str, str] = {}
    marks: dict[str, Decimal] = {}
    expected_ids: tuple[str, ...] | None = None
    previous_sequence = -1
    previous_as_of = ""
    seen_targets: set[str] = set()
    cash = _decimal(request["starting_cash"])
    gross = Decimal(0)
    trade_count = 0
    filled_target_count = 0
    for raw_row in rows:
        if type(raw_row) is not dict or set(raw_row) != {
            "as_of",
            "instruments",
            "sequence",
            "source_batch_sha256",
            "target_id",
        }:
            raise _ProtocolError("row")
        sequence = raw_row["sequence"]
        as_of = raw_row["as_of"]
        if (
            type(sequence) is not int
            or sequence <= previous_sequence
            or type(as_of) is not str
            or not as_of.endswith("Z")
            or as_of <= previous_as_of
        ):
            raise _ProtocolError("order")
        previous_sequence = sequence
        previous_as_of = as_of
        _require_digest(raw_row["source_batch_sha256"])
        raw_instruments = raw_row["instruments"]
        if type(raw_instruments) is not list or not 0 < len(raw_instruments) <= MAX_INSTRUMENTS:
            raise _ProtocolError("instruments")
        parsed: list[tuple[str, str, Decimal, Decimal | None]] = []
        for raw_item in raw_instruments:
            if type(raw_item) is not dict or set(raw_item) != {
                "close_price",
                "instrument_id",
                "symbol",
                "target_quantity",
            }:
                raise _ProtocolError("instrument")
            instrument_id = _require_text(raw_item["instrument_id"])
            symbol = _require_text(raw_item["symbol"], 32)
            if symbol != symbol.upper():
                raise _ProtocolError("symbol")
            close_price = _decimal(raw_item["close_price"])
            if close_price <= 0:
                raise _ProtocolError("price")
            target_quantity = (
                None
                if raw_item["target_quantity"] is None
                else _decimal(raw_item["target_quantity"])
            )
            if target_quantity is not None and (
                target_quantity < 0 or target_quantity != target_quantity.to_integral_value()
            ):
                raise _ProtocolError("quantity")
            parsed.append((instrument_id, symbol, close_price, target_quantity))
        ids = tuple(item[0] for item in parsed)
        if ids != tuple(sorted(set(ids))):
            raise _ProtocolError("instrument-order")
        if expected_ids is None:
            expected_ids = ids
            quantities = {instrument_id: Decimal(0) for instrument_id in ids}
            symbols = {instrument_id: symbol for instrument_id, symbol, _, _ in parsed}
        elif ids != expected_ids:
            raise _ProtocolError("universe")
        elif any(symbols[instrument_id] != symbol for instrument_id, symbol, _, _ in parsed):
            raise _ProtocolError("symbol")
        target_id = raw_row["target_id"]
        if target_id is None:
            if any(item[3] is not None for item in parsed):
                raise _ProtocolError("mark")
        else:
            target_id = _require_text(target_id)
            if target_id in seen_targets or any(item[3] is None for item in parsed):
                raise _ProtocolError("target")
            seen_targets.add(target_id)
            filled_target_count += 1
        marks = {instrument_id: price for instrument_id, _, price, _ in parsed}
        if target_id is None:
            continue
        for instrument_id, _symbol, price, target_quantity in parsed:
            assert target_quantity is not None
            delta = _subtract(target_quantity, quantities[instrument_id])
            if delta == 0:
                continue
            notional = _multiply(delta, price)
            cash = _subtract(cash, notional)
            gross = _add(gross, notional.copy_abs())
            quantities[instrument_id] = target_quantity
            trade_count += 1
    if not seen_targets or expected_ids is None:
        raise _ProtocolError("target")
    positions: list[dict[str, object]] = []
    market_value = Decimal(0)
    for instrument_id in expected_ids:
        value = _multiply(quantities[instrument_id], marks[instrument_id])
        market_value = _add(market_value, value)
        positions.append(
            {
                "instrument_id": instrument_id,
                "mark_price": _decimal_text(marks[instrument_id]),
                "market_value": _decimal_text(value),
                "quantity": _decimal_text(quantities[instrument_id]),
                "symbol": symbols[instrument_id],
            }
        )
    equity = _add(cash, market_value)
    return {
        "ending_cash": _decimal_text(cash),
        "ending_equity": _decimal_text(equity),
        "ending_market_value": _decimal_text(market_value),
        "filled_target_count": filled_target_count,
        "gross_traded_notional": _decimal_text(gross),
        "net_pnl": _decimal_text(_subtract(equity, _decimal(request["starting_cash"]))),
        "positions": positions,
        "request_semantic_sha256": request["request_semantic_sha256"],
        "trade_count": trade_count,
    }


def _main() -> int:
    try:
        # Darwin may replace __CF_USER_TEXT_ENCODING during exec. Reset the
        # process environment to the same closed policy before reading input.
        os.environ.clear()
        os.environ.update(EXPECTED_ENVIRONMENT)
        limits = _apply_resource_limits()
        encoded = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if not encoded or len(encoded) > MAX_REQUEST_BYTES:
            raise _ProtocolError("size")
        request, payload_sha256 = _decode_request(encoded)
        response = _plain_json_bytes(
            {
                "contract_version": CONTRACT_VERSION,
                "isolation": {
                    "environment": sorted(os.environ.items()),
                    "limits": limits,
                    "process_id": os.getpid(),
                    "session_id": os.getsid(0),
                },
                "request_payload_sha256": payload_sha256,
                "result": _evaluate(request),
            }
        )
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
