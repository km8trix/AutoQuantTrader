"""Pure contracts for one-shot supervised strategy subprocesses.

The strategy result is deliberately non-authorizing.  A caller must still
validate any decoded result through the normal strategy, target, risk, and
operational-control boundaries.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
)
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.operational_control import OperationalControlState

STRATEGY_SUPERVISION_CONTRACT_VERSION = "phase5c-strategy-supervision-v1"
STRATEGY_SUBPROCESS_PROTOCOL_VERSION = "phase5c-strategy-json-v1"

STRATEGY_DECISION_WARNING_MICROSECONDS = 2_000_000
STRATEGY_DECISION_DEADLINE_MICROSECONDS = 5_000_000
STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS = 3_000_000

MAX_STRATEGY_REQUEST_BYTES = 1_048_576
MAX_STRATEGY_STDOUT_BYTES = 262_144
MAX_STRATEGY_STDERR_BYTES = 65_536
MAX_STRATEGY_JSON_DEPTH = 32
MAX_STRATEGY_JSON_NODES = 8_192

STRATEGY_FAILURE_PROTECTED_LOOPS = (
    "order",
    "risk",
    "broker_event",
    "cancel",
    "reconciliation",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StrategySupervisionError(ValueError):
    """The local supervision contract is malformed or inconsistently bound."""


class StrategySupervisionConflict(StrategySupervisionError):
    """An immutable invocation identity is bound to different facts."""


class StrategyProtocolError(StrategySupervisionError):
    """A child response is not the exact bounded canonical JSON protocol."""


class StrategyResourceExceeded(StrategySupervisionError):
    """A request cannot fit inside the fixed subprocess resource envelope."""


class StrategySupervisionOutcome(StrEnum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    CRASH = "crash"
    PROTOCOL_ERROR = "protocol_error"
    RESOURCE_EXCEEDED = "resource_exceeded"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise StrategySupervisionError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise StrategySupervisionError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise StrategySupervisionError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise StrategySupervisionError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise StrategySupervisionError(f"{field_name} must be UTC")


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _plain_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise StrategyProtocolError("strategy JSON value is not canonically encodable") from error


def _reject_json_number(_value: str) -> object:
    raise StrategyProtocolError("strategy JSON protocol does not permit floating-point numbers")


def _reject_json_constant(_value: str) -> object:
    raise StrategyProtocolError("strategy JSON protocol does not permit non-finite constants")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StrategyProtocolError(f"strategy JSON repeats object key {key!r}")
        result[key] = value
    return result


def _validate_json_tree(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > MAX_STRATEGY_JSON_NODES:
            raise StrategyProtocolError("strategy JSON exceeds the node limit")
        if depth > MAX_STRATEGY_JSON_DEPTH:
            raise StrategyProtocolError("strategy JSON exceeds the nesting limit")
        if node is None or type(node) in {bool, str}:
            continue
        if type(node) is int:
            if not -(2**63) <= node <= 2**63 - 1:
                raise StrategyProtocolError("strategy JSON integer exceeds signed 64-bit range")
            continue
        if type(node) is list:
            pending.extend((item, depth + 1) for item in node)
            continue
        if type(node) is dict:
            if any(type(key) is not str for key in node):
                raise StrategyProtocolError("strategy JSON object keys must be strings")
            pending.extend((item, depth + 1) for item in node.values())
            continue
        raise StrategyProtocolError("strategy JSON contains an unsupported value")


def _decode_canonical_json(payload: bytes) -> object:
    if not payload:
        raise StrategyProtocolError("strategy response is empty")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_constant,
        )
    except StrategyProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise StrategyProtocolError("strategy response is not valid UTF-8 JSON") from error
    _validate_json_tree(value)
    if _plain_json_bytes(value) != payload:
        raise StrategyProtocolError("strategy response must use canonical JSON encoding")
    return value


@dataclass(frozen=True, slots=True)
class StrategyRuntimeBinding:
    """Exact child artifact and launch contract selected for one invocation."""

    runtime_id: str
    runtime_version: str
    artifact_sha256: str
    launch_spec_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.runtime_id, "strategy runtime ID")
        _require_text(self.runtime_version, "strategy runtime version")
        _require_sha256(self.artifact_sha256, "strategy runtime artifact_sha256")
        _require_sha256(self.launch_spec_sha256, "strategy runtime launch_spec_sha256")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_SUPERVISION_CONTRACT_VERSION,
                "runtime_binding",
                self.runtime_id,
                self.runtime_version,
                self.artifact_sha256,
                self.launch_spec_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class StrategyInvocation:
    """One immutable invocation bound to all inputs that may affect its result."""

    control_scope_id: str
    environment: str
    market_batch_id: str
    market_batch_sha256: str
    market_batch_as_of: datetime
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    input_state_sha256: str
    runtime: StrategyRuntimeBinding
    requested_at: datetime
    protocol_version: str = STRATEGY_SUBPROCESS_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.control_scope_id, "strategy control scope ID"),
            (self.environment, "strategy environment"),
            (self.market_batch_id, "strategy market batch ID"),
            (self.strategy_id, "strategy ID"),
            (self.strategy_version, "strategy version"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.market_batch_sha256, "strategy market_batch_sha256")
        _require_sha256(
            self.strategy_configuration_sha256,
            "strategy configuration_sha256",
        )
        _require_sha256(self.input_state_sha256, "strategy input_state_sha256")
        _require_utc(self.market_batch_as_of, "strategy market_batch_as_of")
        _require_utc(self.requested_at, "strategy requested_at")
        if self.requested_at < self.market_batch_as_of:
            raise StrategySupervisionError("strategy invocation cannot predate its market batch")
        if type(self.runtime) is not StrategyRuntimeBinding:
            raise StrategySupervisionError("strategy invocation requires an exact runtime binding")
        if self.protocol_version != STRATEGY_SUBPROCESS_PROTOCOL_VERSION:
            raise StrategySupervisionError("strategy invocation protocol version is unsupported")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_SUPERVISION_CONTRACT_VERSION,
                "invocation",
                self.control_scope_id,
                self.environment,
                self.market_batch_id,
                self.market_batch_sha256,
                self.market_batch_as_of,
                self.strategy_id,
                self.strategy_version,
                self.strategy_configuration_sha256,
                self.input_state_sha256,
                self.runtime.semantic_sha256,
                self.requested_at,
                self.protocol_version,
                STRATEGY_DECISION_WARNING_MICROSECONDS,
                STRATEGY_DECISION_DEADLINE_MICROSECONDS,
                MAX_STRATEGY_REQUEST_BYTES,
                MAX_STRATEGY_STDOUT_BYTES,
                MAX_STRATEGY_STDERR_BYTES,
            )
        )

    @property
    def invocation_id(self) -> str:
        return canonical_id("strategy-invocation", self.semantic_sha256)

    def require_batch(self, batch: MarketBatch) -> None:
        if type(batch) is not MarketBatch:
            raise StrategySupervisionConflict(
                "strategy invocation requires an exact sealed market batch"
            )
        batch._validate()
        if not batch.complete:
            raise StrategySupervisionConflict(
                "strategy invocation requires a watermark-complete market batch"
            )
        observed = (batch.batch_id, batch.semantic_sha256, batch.as_of)
        expected = (
            self.market_batch_id,
            self.market_batch_sha256,
            self.market_batch_as_of,
        )
        if observed != expected:
            raise StrategySupervisionConflict(
                "strategy invocation is not bound to the supplied market batch"
            )

    def require_runtime(self, runtime: StrategyRuntimeBinding) -> None:
        if type(runtime) is not StrategyRuntimeBinding or runtime != self.runtime:
            raise StrategySupervisionConflict(
                "strategy invocation is not bound to the supplied runtime"
            )


def bind_strategy_invocation(
    *,
    control_scope_id: str,
    environment: str,
    market_batch: MarketBatch,
    strategy_id: str,
    strategy_version: str,
    strategy_configuration_sha256: str,
    input_state_sha256: str,
    runtime: StrategyRuntimeBinding,
    requested_at: datetime,
) -> StrategyInvocation:
    """Bind one complete market batch to an exact strategy and child runtime."""

    if type(market_batch) is not MarketBatch:
        raise StrategySupervisionError("strategy invocation requires an exact sealed market batch")
    market_batch._validate()
    if not market_batch.complete:
        raise StrategySupervisionError(
            "strategy invocation requires a watermark-complete market batch"
        )
    invocation = StrategyInvocation(
        control_scope_id=control_scope_id,
        environment=environment,
        market_batch_id=market_batch.batch_id,
        market_batch_sha256=market_batch.semantic_sha256,
        market_batch_as_of=market_batch.as_of,
        strategy_id=strategy_id,
        strategy_version=strategy_version,
        strategy_configuration_sha256=strategy_configuration_sha256,
        input_state_sha256=input_state_sha256,
        runtime=runtime,
        requested_at=requested_at,
    )
    invocation.require_batch(market_batch)
    return invocation


def _event_json(event: object) -> dict[str, object]:
    from packages.domain.models import MarketEvent

    if type(event) is not MarketEvent:
        raise StrategySupervisionConflict("strategy market batch contains a noncanonical event")
    return {
        "available_at": _utc_text(event.available_at),
        "close_price": canonical_decimal_text(event.close_price),
        "event_id": event.event_id,
        "event_time": _utc_text(event.event_time),
        "instrument_id": event.instrument_id,
        "observation_id": event.observation_key,
        "revision": event.revision,
        "source": event.source,
        "source_sequence": event.source_sequence,
        "supersedes_event_revision_id": event.supersedes_event_revision_id,
        "symbol": event.symbol,
    }


def encode_strategy_request(
    invocation: StrategyInvocation,
    market_batch: MarketBatch,
) -> bytes:
    """Encode the only request accepted by a supervised child.

    Exact Decimal values use canonical coefficient/exponent strings.  This
    protocol intentionally does not transport binary floats.
    """

    if type(invocation) is not StrategyInvocation:
        raise StrategySupervisionError("strategy request requires an exact invocation")
    invocation.require_batch(market_batch)
    watermark = market_batch.watermark
    payload = {
        "invocation": {
            "control_scope_id": invocation.control_scope_id,
            "environment": invocation.environment,
            "id": invocation.invocation_id,
            "input_state_sha256": invocation.input_state_sha256,
            "market_batch_as_of": _utc_text(invocation.market_batch_as_of),
            "market_batch_id": invocation.market_batch_id,
            "market_batch_sha256": invocation.market_batch_sha256,
            "requested_at": _utc_text(invocation.requested_at),
            "runtime": {
                "artifact_sha256": invocation.runtime.artifact_sha256,
                "id": invocation.runtime.runtime_id,
                "launch_spec_sha256": invocation.runtime.launch_spec_sha256,
                "semantic_sha256": invocation.runtime.semantic_sha256,
                "version": invocation.runtime.runtime_version,
            },
            "semantic_sha256": invocation.semantic_sha256,
            "strategy_configuration_sha256": invocation.strategy_configuration_sha256,
            "strategy_id": invocation.strategy_id,
            "strategy_version": invocation.strategy_version,
        },
        "market_batch": {
            "as_of": _utc_text(market_batch.as_of),
            "events": [_event_json(event) for event in market_batch.events],
            "id": market_batch.batch_id,
            "semantic_sha256": market_batch.semantic_sha256,
            "watermark": {
                "closed_at": _utc_text(watermark.closed_at),
                "event_time_through": _utc_text(watermark.event_time_through),
                "expected_instrument_ids": list(watermark.expected_instrument_ids),
                "id": watermark.watermark_id,
                "late_event_policy": watermark.late_event_policy.value,
                "missing_data_policy": watermark.missing_data_policy.value,
                "revision_policy": watermark.revision_policy.value,
            },
        },
        "protocol_version": invocation.protocol_version,
    }
    encoded = _plain_json_bytes(payload)
    if len(encoded) > MAX_STRATEGY_REQUEST_BYTES:
        raise StrategyResourceExceeded("strategy request exceeds the fixed request byte limit")
    return encoded


@dataclass(frozen=True, slots=True)
class StrategyProtocolResponse:
    invocation_id: str
    invocation_sha256: str
    protocol_version: str
    result_json: str
    result_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.invocation_id, "strategy response invocation ID")
        _require_sha256(self.invocation_sha256, "strategy response invocation_sha256")
        if self.protocol_version != STRATEGY_SUBPROCESS_PROTOCOL_VERSION:
            raise StrategyProtocolError("strategy response protocol version is unsupported")
        try:
            result_bytes = self.result_json.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise StrategyProtocolError("strategy result is not valid UTF-8") from error
        _decode_canonical_json(result_bytes)
        _require_sha256(self.result_sha256, "strategy response result_sha256")
        if _sha256_bytes(result_bytes) != self.result_sha256:
            raise StrategyProtocolError("strategy response result digest is inconsistent")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_SUPERVISION_CONTRACT_VERSION,
                "protocol_response",
                self.invocation_id,
                self.invocation_sha256,
                self.protocol_version,
                self.result_sha256,
            )
        )


def decode_strategy_response(
    payload: bytes,
    invocation: StrategyInvocation,
) -> StrategyProtocolResponse:
    """Decode one exact canonical response, allowing at most one final LF."""

    if type(payload) is not bytes:
        raise StrategyProtocolError("strategy response must be exact bytes")
    if len(payload) > MAX_STRATEGY_STDOUT_BYTES:
        raise StrategyResourceExceeded("strategy response exceeds the fixed stdout byte limit")
    if type(invocation) is not StrategyInvocation:
        raise StrategyProtocolError("strategy response requires an exact invocation")
    body = payload[:-1] if payload.endswith(b"\n") else payload
    decoded = _decode_canonical_json(body)
    if type(decoded) is not dict:
        raise StrategyProtocolError("strategy response envelope must be an object")
    expected_keys = {
        "invocation_id",
        "invocation_sha256",
        "protocol_version",
        "result",
    }
    if set(decoded) != expected_keys:
        raise StrategyProtocolError("strategy response envelope has missing or unsupported fields")
    if decoded["invocation_id"] != invocation.invocation_id:
        raise StrategyProtocolError("strategy response has the wrong invocation ID")
    if decoded["invocation_sha256"] != invocation.semantic_sha256:
        raise StrategyProtocolError("strategy response has the wrong invocation digest")
    if decoded["protocol_version"] != invocation.protocol_version:
        raise StrategyProtocolError("strategy response has the wrong protocol version")
    result_bytes = _plain_json_bytes(decoded["result"])
    result_json = result_bytes.decode("utf-8")
    return StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=invocation.protocol_version,
        result_json=result_json,
        result_sha256=_sha256_bytes(result_bytes),
    )


@dataclass(frozen=True, slots=True)
class StrategySupervisionResult:
    """Immutable observation from one child; never an exposure authorization."""

    invocation_id: str
    invocation_sha256: str
    outcome: StrategySupervisionOutcome
    started_at: datetime
    completed_at: datetime
    elapsed_microseconds: int
    process_started: bool
    exit_code: int | None
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    detail_code: str
    response: StrategyProtocolResponse | None = None

    def __post_init__(self) -> None:
        _require_text(self.invocation_id, "strategy result invocation ID")
        _require_sha256(self.invocation_sha256, "strategy result invocation_sha256")
        if type(self.outcome) is not StrategySupervisionOutcome:
            raise StrategySupervisionError("strategy result outcome is unsupported")
        _require_utc(self.started_at, "strategy result started_at")
        _require_utc(self.completed_at, "strategy result completed_at")
        if self.completed_at < self.started_at:
            raise StrategySupervisionError("strategy result completion cannot precede its start")
        if type(self.elapsed_microseconds) is not int or self.elapsed_microseconds < 0:
            raise StrategySupervisionError(
                "strategy result elapsed_microseconds must be non-negative"
            )
        if type(self.process_started) is not bool:
            raise StrategySupervisionError("strategy result process_started must be boolean")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise StrategySupervisionError("strategy result exit_code must be an integer")
        for value, field_name in (
            (self.stdout_bytes, "strategy result stdout_bytes"),
            (self.stderr_bytes, "strategy result stderr_bytes"),
        ):
            if type(value) is not int or value < 0:
                raise StrategySupervisionError(f"{field_name} must be non-negative")
        _require_sha256(self.stdout_sha256, "strategy result stdout_sha256")
        _require_sha256(self.stderr_sha256, "strategy result stderr_sha256")
        _require_text(self.detail_code, "strategy result detail code")
        if self.outcome is StrategySupervisionOutcome.COMPLETED:
            if (
                not self.process_started
                or self.exit_code != 0
                or type(self.response) is not StrategyProtocolResponse
            ):
                raise StrategySupervisionError(
                    "completed strategy result requires a successful child response"
                )
            if (
                self.response.invocation_id != self.invocation_id
                or self.response.invocation_sha256 != self.invocation_sha256
            ):
                raise StrategySupervisionConflict(
                    "strategy result response crosses invocation identities"
                )
        elif self.response is not None:
            raise StrategySupervisionError(
                "failed strategy result cannot retain an accepted response"
            )
        if (
            self.outcome is StrategySupervisionOutcome.TIMEOUT
            and self.elapsed_microseconds < STRATEGY_DECISION_DEADLINE_MICROSECONDS
        ):
            raise StrategySupervisionError(
                "strategy timeout cannot precede the hard decision deadline"
            )
        if not self.process_started and self.exit_code is not None:
            raise StrategySupervisionError("an unstarted strategy process cannot have an exit code")

    @property
    def warning_threshold_exceeded(self) -> bool:
        return self.elapsed_microseconds >= STRATEGY_DECISION_WARNING_MICROSECONDS

    @property
    def blocks_new_exposure(self) -> bool:
        return self.outcome is not StrategySupervisionOutcome.COMPLETED

    @property
    def requested_control_state(self) -> OperationalControlState | None:
        if self.blocks_new_exposure:
            return OperationalControlState.PAUSED
        return None

    @property
    def protected_runtime_loops(self) -> tuple[str, ...]:
        return STRATEGY_FAILURE_PROTECTED_LOOPS

    @property
    def automatic_resume_authorized(self) -> bool:
        return False

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_SUPERVISION_CONTRACT_VERSION,
                "result",
                self.invocation_id,
                self.invocation_sha256,
                self.outcome,
                self.started_at,
                self.completed_at,
                self.elapsed_microseconds,
                self.process_started,
                self.exit_code,
                self.stdout_bytes,
                self.stdout_sha256,
                self.stderr_bytes,
                self.stderr_sha256,
                self.detail_code,
                None if self.response is None else self.response.semantic_sha256,
                self.requested_control_state,
                self.protected_runtime_loops,
                self.automatic_resume_authorized,
            )
        )
