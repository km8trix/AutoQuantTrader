"""Pure contracts for bounded Phase 3H fixture-segment economics.

The contract accepts only an already-completed Phase 3F projection and its
exact parity-certified target transcript.  It models immediate, zero-cost
fills at the repository fixture's causal close prices.  The result is internal
research evidence: it cannot qualify captured data, decide promotion, or
authorize any broker or trading effect.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Self

from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.feature_target import (
    CertifiedFeatureTargetReplay,
    FeatureTargetStepStatus,
)
from packages.domain.fixture_segment_worker import (
    FixtureSegmentJobProjection,
    FixtureSegmentJobStatus,
    FixtureTranscriptArtifact,
    FixtureTranscriptKind,
)

FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION = "phase3h-fixture-economic-segment-v1"
FIXTURE_ECONOMIC_MODEL_VERSION = "immediate-causal-close-zero-cost-v1"
FIXTURE_ECONOMIC_STARTING_CASH = Decimal("100000")
MAX_FIXTURE_ECONOMIC_ROWS = 2_048
MAX_FIXTURE_ECONOMIC_INSTRUMENTS = 64
MAX_FIXTURE_ECONOMIC_REQUEST_BYTES = 262_144
MAX_FIXTURE_ECONOMIC_STDOUT_BYTES = 65_536
MAX_FIXTURE_ECONOMIC_STDERR_BYTES = 16_384
FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS = 3_000
FIXTURE_ECONOMIC_CPU_SECONDS = 2
FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS = (
    ("darwin", 1_099_511_627_776),
    ("linux", 536_870_912),
)
FIXTURE_ECONOMIC_OPEN_FILES = 16
FIXTURE_ECONOMIC_FILE_BYTES = 0
FIXTURE_ECONOMIC_CHILD_PROCESSES = 0

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FACTORY_PROOF = object()


class FixtureEconomicSegmentError(ValueError):
    """Fixture economic evidence is malformed, substituted, or unsupported."""


class FixtureEconomicProcessOutcome(StrEnum):
    COMPLETED = "completed"
    SPAWN_FAILED = "spawn_failed"
    TIMEOUT = "timeout"
    RESOURCE_EXCEEDED = "resource_exceeded"
    CRASHED = "crashed"
    PROTOCOL_ERROR = "protocol_error"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FixtureEconomicSegmentError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise FixtureEconomicSegmentError(f"{field_name} must be bounded non-empty trimmed text")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise FixtureEconomicSegmentError(f"{field_name} must be an aware UTC datetime")


def _decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise FixtureEconomicSegmentError(f"{field_name} must be an exact finite Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise FixtureEconomicSegmentError(str(error)) from error


@dataclass(frozen=True, slots=True)
class FixtureEconomicInstrumentInput:
    instrument_id: str
    symbol: str
    close_price: Decimal
    target_quantity: Decimal | None

    def __post_init__(self) -> None:
        _require_text(self.instrument_id, "economic instrument ID")
        _require_text(self.symbol, "economic instrument symbol", maximum=32)
        if self.symbol != self.symbol.upper():
            raise FixtureEconomicSegmentError("economic instrument symbol must be uppercase")
        price = _decimal(self.close_price, "economic close price")
        if price <= 0:
            raise FixtureEconomicSegmentError("economic close price must be positive")
        object.__setattr__(self, "close_price", price)
        if self.target_quantity is not None:
            quantity = _decimal(self.target_quantity, "economic target quantity")
            if quantity < 0 or quantity != quantity.to_integral_value():
                raise FixtureEconomicSegmentError(
                    "economic target quantity must be non-negative and whole"
                )
            object.__setattr__(self, "target_quantity", quantity)

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "instrument-input",
                self.instrument_id,
                self.symbol,
                self.close_price,
                self.target_quantity,
            )
        )


@dataclass(frozen=True, slots=True)
class FixtureEconomicRow:
    sequence: int
    as_of: datetime
    source_batch_sha256: str
    target_id: str | None
    instruments: tuple[FixtureEconomicInstrumentInput, ...]

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise FixtureEconomicSegmentError("economic row sequence must be non-negative")
        _require_utc(self.as_of, "economic row as_of")
        _require_sha256(self.source_batch_sha256, "economic source batch digest")
        if type(self.instruments) is not tuple or not self.instruments:
            raise FixtureEconomicSegmentError("economic row requires immutable instruments")
        if len(self.instruments) > MAX_FIXTURE_ECONOMIC_INSTRUMENTS:
            raise FixtureEconomicSegmentError("economic row exceeds the instrument bound")
        if any(type(item) is not FixtureEconomicInstrumentInput for item in self.instruments):
            raise FixtureEconomicSegmentError("economic row contains a noncanonical instrument")
        for item in self.instruments:
            item.__post_init__()
        instrument_ids = tuple(item.instrument_id for item in self.instruments)
        if instrument_ids != tuple(sorted(set(instrument_ids))):
            raise FixtureEconomicSegmentError(
                "economic row instruments must be unique and canonically ordered"
            )
        has_quantities = tuple(item.target_quantity is not None for item in self.instruments)
        if self.target_id is None:
            if any(has_quantities):
                raise FixtureEconomicSegmentError(
                    "mark-only economic row cannot carry target quantities"
                )
        else:
            _require_text(self.target_id, "economic target ID")
            if not all(has_quantities):
                raise FixtureEconomicSegmentError(
                    "target economic row requires every target quantity"
                )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-row",
                self.sequence,
                self.as_of,
                self.source_batch_sha256,
                self.target_id,
                tuple(item.semantic_sha256 for item in self.instruments),
            )
        )


@dataclass(frozen=True, slots=True)
class FixtureEconomicSegmentRequest:
    job_id: str
    family_id: str
    attempt_id: str
    configuration_sha256: str
    segment_kind: str
    segment_sha256: str
    completion_receipt_sha256: str
    target_artifact_sha256: str
    target_certification_sha256: str
    target_transcript_sha256: str
    rows: tuple[FixtureEconomicRow, ...]
    starting_cash: Decimal = FIXTURE_ECONOMIC_STARTING_CASH
    model_version: str = FIXTURE_ECONOMIC_MODEL_VERSION

    def __post_init__(self) -> None:
        _require_sha256(self.job_id, "economic job ID")
        _require_sha256(self.family_id, "economic family ID")
        _require_sha256(self.attempt_id, "economic attempt ID")
        for value, field_name in (
            (self.configuration_sha256, "economic configuration digest"),
            (self.segment_sha256, "economic segment digest"),
            (self.completion_receipt_sha256, "economic completion receipt digest"),
            (self.target_artifact_sha256, "economic target artifact digest"),
            (self.target_certification_sha256, "economic target certification digest"),
            (self.target_transcript_sha256, "economic target transcript digest"),
        ):
            _require_sha256(value, field_name)
        if self.segment_kind not in {"train", "validation", "test"}:
            raise FixtureEconomicSegmentError("economic segment kind is unsupported")
        if self.model_version != FIXTURE_ECONOMIC_MODEL_VERSION:
            raise FixtureEconomicSegmentError("economic model version is unsupported")
        cash = _decimal(self.starting_cash, "economic starting cash")
        if cash != FIXTURE_ECONOMIC_STARTING_CASH:
            raise FixtureEconomicSegmentError("economic starting cash must remain exact")
        object.__setattr__(self, "starting_cash", cash)
        if type(self.rows) is not tuple or not self.rows:
            raise FixtureEconomicSegmentError("economic request requires immutable rows")
        if len(self.rows) > MAX_FIXTURE_ECONOMIC_ROWS:
            raise FixtureEconomicSegmentError("economic request exceeds the row bound")
        if any(type(row) is not FixtureEconomicRow for row in self.rows):
            raise FixtureEconomicSegmentError("economic request contains a noncanonical row")
        expected_ids = tuple(item.instrument_id for item in self.rows[0].instruments)
        expected_symbols = tuple(item.symbol for item in self.rows[0].instruments)
        previous_sequence = -1
        previous_time: datetime | None = None
        target_count = 0
        target_ids: set[str] = set()
        for row in self.rows:
            row.__post_init__()
            if row.sequence <= previous_sequence:
                raise FixtureEconomicSegmentError(
                    "economic rows must retain strictly increasing source order"
                )
            if previous_time is not None and row.as_of <= previous_time:
                raise FixtureEconomicSegmentError(
                    "economic rows must retain strictly increasing causal time"
                )
            if tuple(item.instrument_id for item in row.instruments) != expected_ids:
                raise FixtureEconomicSegmentError(
                    "bounded economic fixture cannot change its instrument universe"
                )
            if tuple(item.symbol for item in row.instruments) != expected_symbols:
                raise FixtureEconomicSegmentError(
                    "bounded economic fixture cannot change instrument symbols"
                )
            previous_sequence = row.sequence
            previous_time = row.as_of
            if row.target_id is not None:
                if row.target_id in target_ids:
                    raise FixtureEconomicSegmentError("economic target IDs must be unique")
                target_ids.add(row.target_id)
                target_count += 1
        if target_count == 0:
            raise FixtureEconomicSegmentError("economic request requires at least one target")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-request",
                self.job_id,
                self.family_id,
                self.attempt_id,
                self.configuration_sha256,
                self.segment_kind,
                self.segment_sha256,
                self.completion_receipt_sha256,
                self.target_artifact_sha256,
                self.target_certification_sha256,
                self.target_transcript_sha256,
                self.model_version,
                self.starting_cash,
                tuple(row.semantic_sha256 for row in self.rows),
            )
        )

    @property
    def target_count(self) -> int:
        return sum(row.target_id is not None for row in self.rows)


@dataclass(frozen=True, slots=True)
class FixtureEconomicPosition:
    instrument_id: str
    symbol: str
    quantity: Decimal
    mark_price: Decimal
    market_value: Decimal

    def __post_init__(self) -> None:
        _require_text(self.instrument_id, "economic position instrument ID")
        _require_text(self.symbol, "economic position symbol", maximum=32)
        if self.symbol != self.symbol.upper():
            raise FixtureEconomicSegmentError("economic position symbol must be uppercase")
        quantity = _decimal(self.quantity, "economic position quantity")
        price = _decimal(self.mark_price, "economic position mark price")
        value = _decimal(self.market_value, "economic position market value")
        if quantity < 0 or quantity != quantity.to_integral_value() or price <= 0:
            raise FixtureEconomicSegmentError("economic position is outside the long-only model")
        if value != exact_decimal_multiply(quantity, price):
            raise FixtureEconomicSegmentError("economic position value is inconsistent")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "mark_price", price)
        object.__setattr__(self, "market_value", value)

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-position",
                self.instrument_id,
                self.symbol,
                self.quantity,
                self.mark_price,
                self.market_value,
            )
        )


@dataclass(frozen=True, slots=True)
class FixtureEconomicSegmentResult:
    request_sha256: str
    ending_cash: Decimal
    ending_market_value: Decimal
    ending_equity: Decimal
    net_pnl: Decimal
    gross_traded_notional: Decimal
    trade_count: int
    filled_target_count: int
    positions: tuple[FixtureEconomicPosition, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.request_sha256, "economic result request digest")
        for field_name in (
            "ending_cash",
            "ending_market_value",
            "ending_equity",
            "net_pnl",
            "gross_traded_notional",
        ):
            object.__setattr__(self, field_name, _decimal(getattr(self, field_name), field_name))
        if self.gross_traded_notional < 0:
            raise FixtureEconomicSegmentError("economic gross notional must be non-negative")
        for value, field_name in (
            (self.trade_count, "economic trade count"),
            (self.filled_target_count, "economic filled-target count"),
        ):
            if type(value) is not int or value < 0:
                raise FixtureEconomicSegmentError(f"{field_name} must be non-negative")
        if self.trade_count > MAX_FIXTURE_ECONOMIC_ROWS * MAX_FIXTURE_ECONOMIC_INSTRUMENTS:
            raise FixtureEconomicSegmentError("economic trade count exceeds its bound")
        if not 0 < self.filled_target_count <= MAX_FIXTURE_ECONOMIC_ROWS:
            raise FixtureEconomicSegmentError("economic filled-target count is outside its bound")
        if type(self.positions) is not tuple or any(
            type(position) is not FixtureEconomicPosition for position in self.positions
        ):
            raise FixtureEconomicSegmentError("economic positions must be immutable exact values")
        for position in self.positions:
            position.__post_init__()
        instrument_ids = tuple(position.instrument_id for position in self.positions)
        if instrument_ids != tuple(sorted(set(instrument_ids))):
            raise FixtureEconomicSegmentError(
                "economic positions must be unique and canonically ordered"
            )
        if self.ending_market_value != exact_decimal_sum(
            tuple(position.market_value for position in self.positions)
        ):
            raise FixtureEconomicSegmentError("economic market value is inconsistent")
        if self.ending_equity != exact_decimal_add(
            self.ending_cash,
            self.ending_market_value,
        ):
            raise FixtureEconomicSegmentError("economic ending equity is inconsistent")
        if self.net_pnl != exact_decimal_subtract(
            self.ending_equity,
            FIXTURE_ECONOMIC_STARTING_CASH,
        ):
            raise FixtureEconomicSegmentError("economic P&L is inconsistent")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-result",
                self.request_sha256,
                self.ending_cash,
                self.ending_market_value,
                self.ending_equity,
                self.net_pnl,
                self.gross_traded_notional,
                self.trade_count,
                self.filled_target_count,
                tuple(position.semantic_sha256 for position in self.positions),
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FixtureEconomicProcessEvidence:
    """Bounded successful child-process observation; raw streams are excluded."""

    runtime_artifact_sha256: str
    launch_spec_sha256: str
    isolation_profile_sha256: str
    request_bytes: int
    request_payload_sha256: str
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    exit_code: int
    elapsed_microseconds: int
    process_started: bool
    outcome: FixtureEconomicProcessOutcome

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fixture economic process evidence is supervisor-constructed")

    @classmethod
    def _from_supervisor(
        cls,
        *,
        runtime_artifact_sha256: str,
        launch_spec_sha256: str,
        request_bytes: int,
        request_payload_sha256: str,
        stdout_bytes: int,
        stdout_sha256: str,
        stderr_bytes: int,
        stderr_sha256: str,
        elapsed_microseconds: int,
    ) -> Self:
        instance = object.__new__(cls)
        values: dict[str, object] = {
            "runtime_artifact_sha256": runtime_artifact_sha256,
            "launch_spec_sha256": launch_spec_sha256,
            "isolation_profile_sha256": fixture_economic_isolation_profile_sha256(),
            "request_bytes": request_bytes,
            "request_payload_sha256": request_payload_sha256,
            "stdout_bytes": stdout_bytes,
            "stdout_sha256": stdout_sha256,
            "stderr_bytes": stderr_bytes,
            "stderr_sha256": stderr_sha256,
            "exit_code": 0,
            "elapsed_microseconds": elapsed_microseconds,
            "process_started": True,
            "outcome": FixtureEconomicProcessOutcome.COMPLETED,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    def _validate(self) -> None:
        for value, field_name in (
            (self.runtime_artifact_sha256, "economic runtime artifact digest"),
            (self.launch_spec_sha256, "economic launch spec digest"),
            (self.isolation_profile_sha256, "economic isolation profile digest"),
            (self.request_payload_sha256, "economic request payload digest"),
            (self.stdout_sha256, "economic stdout digest"),
            (self.stderr_sha256, "economic stderr digest"),
        ):
            _require_sha256(value, field_name)
        if self.isolation_profile_sha256 != fixture_economic_isolation_profile_sha256():
            raise FixtureEconomicSegmentError("economic isolation profile was substituted")
        if not 0 < self.request_bytes <= MAX_FIXTURE_ECONOMIC_REQUEST_BYTES:
            raise FixtureEconomicSegmentError("economic request byte count is outside its bound")
        if not 0 < self.stdout_bytes <= MAX_FIXTURE_ECONOMIC_STDOUT_BYTES:
            raise FixtureEconomicSegmentError("economic stdout byte count is outside its bound")
        if not 0 <= self.stderr_bytes <= MAX_FIXTURE_ECONOMIC_STDERR_BYTES:
            raise FixtureEconomicSegmentError("economic stderr byte count is outside its bound")
        if self.exit_code != 0 or self.outcome is not FixtureEconomicProcessOutcome.COMPLETED:
            raise FixtureEconomicSegmentError("economic process evidence is not successful")
        if type(self.elapsed_microseconds) is not int or self.elapsed_microseconds < 0:
            raise FixtureEconomicSegmentError("economic elapsed time must be non-negative")
        if self.elapsed_microseconds > FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS * 1_000:
            raise FixtureEconomicSegmentError("economic process exceeded its wall-time bound")
        if self.process_started is not True:
            raise FixtureEconomicSegmentError("economic process evidence requires a child")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-process-evidence",
                self.runtime_artifact_sha256,
                self.launch_spec_sha256,
                self.isolation_profile_sha256,
                self.request_bytes,
                self.request_payload_sha256,
                self.stdout_bytes,
                self.stdout_sha256,
                self.stderr_bytes,
                self.stderr_sha256,
                self.exit_code,
                self.elapsed_microseconds,
                self.process_started,
                self.outcome.value,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FixtureEconomicSegmentReceipt:
    request: FixtureEconomicSegmentRequest
    result: FixtureEconomicSegmentResult
    process: FixtureEconomicProcessEvidence
    receipt_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fixture economic receipts are proof-constructed")

    @classmethod
    def _from_verified_execution(
        cls,
        request: FixtureEconomicSegmentRequest,
        result: FixtureEconomicSegmentResult,
        process: FixtureEconomicProcessEvidence,
    ) -> Self:
        if type(request) is not FixtureEconomicSegmentRequest:
            raise FixtureEconomicSegmentError("economic receipt requires an exact request")
        request.__post_init__()
        if type(result) is not FixtureEconomicSegmentResult:
            raise FixtureEconomicSegmentError("economic receipt requires an exact result")
        result.__post_init__()
        if type(process) is not FixtureEconomicProcessEvidence:
            raise FixtureEconomicSegmentError("economic receipt requires exact process evidence")
        process._validate()
        expected = evaluate_fixture_economic_request(request)
        if result != expected:
            raise FixtureEconomicSegmentError(
                "economic child result conflicts with independent parent evaluation"
            )
        instance = object.__new__(cls)
        object.__setattr__(instance, "request", request)
        object.__setattr__(instance, "result", result)
        object.__setattr__(instance, "process", process)
        object.__setattr__(instance, "receipt_sha256", _sha256(instance._semantic_material()))
        return instance

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
            "economic-receipt",
            self.request.semantic_sha256,
            self.result.semantic_sha256,
            self.process.semantic_sha256,
            self.counts_as_captured_tape_evidence,
            self.promotion_authorized,
            self.provider_io_authorized,
            self.broker_effect_authorized,
            self.trading_authorized,
            self.public_view_authorized,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.receipt_sha256

    @property
    def counts_as_captured_tape_evidence(self) -> bool:
        return False

    @property
    def promotion_authorized(self) -> bool:
        return False

    @property
    def provider_io_authorized(self) -> bool:
        return False

    @property
    def broker_effect_authorized(self) -> bool:
        return False

    @property
    def trading_authorized(self) -> bool:
        return False

    @property
    def public_view_authorized(self) -> bool:
        return False


def fixture_economic_isolation_profile_sha256() -> str:
    return _sha256(
        (
            FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
            "process-isolation-profile",
            "repository-owned-stdlib-child",
            "absolute-python-executable",
            ("-I", "-S", "-B"),
            "shell-false",
            "close-fds-true",
            "new-process-session",
            "fixed-empty-cwd",
            "fixed-environment",
            "stdin-stdout-stderr-pipes",
            FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS,
            FIXTURE_ECONOMIC_CPU_SECONDS,
            FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS,
            FIXTURE_ECONOMIC_OPEN_FILES,
            FIXTURE_ECONOMIC_FILE_BYTES,
            FIXTURE_ECONOMIC_CHILD_PROCESSES,
            MAX_FIXTURE_ECONOMIC_REQUEST_BYTES,
            MAX_FIXTURE_ECONOMIC_STDOUT_BYTES,
            MAX_FIXTURE_ECONOMIC_STDERR_BYTES,
        )
    )


def bind_fixture_economic_request(
    projection: FixtureSegmentJobProjection,
    certification: CertifiedFeatureTargetReplay,
) -> FixtureEconomicSegmentRequest:
    """Bind exact Phase 3F completion evidence to the closed fixture model."""

    if type(projection) is not FixtureSegmentJobProjection:
        raise FixtureEconomicSegmentError("economic execution requires an exact projection")
    projection.__post_init__()
    if (
        projection.status is not FixtureSegmentJobStatus.COMPLETED
        or type(projection.target_artifact) is not FixtureTranscriptArtifact
        or projection.target_artifact.kind is not FixtureTranscriptKind.TARGET
        or projection.latest.completion_receipt_sha256 is None
    ):
        raise FixtureEconomicSegmentError(
            "economic execution requires completed authenticated Phase 3F evidence"
        )
    if type(certification) is not CertifiedFeatureTargetReplay:
        raise FixtureEconomicSegmentError("economic execution requires exact target evidence")
    try:
        certification.__post_init__()
    except ValueError as error:
        raise FixtureEconomicSegmentError("economic target evidence is inconsistent") from error
    artifact = projection.target_artifact
    receipt = certification.receipt
    if (
        artifact.family_id != projection.job.family_id
        or artifact.attempt_id != projection.job.attempt_id
        or artifact.configuration_sha256 != projection.job.configuration_sha256
        or artifact.certification_sha256 != certification.semantic_sha256
        or artifact.parity_receipt_sha256 != receipt.semantic_sha256
        or artifact.transcript_sha256 != certification.batch_result.transcript_sha256
        or artifact.step_sha256s
        != tuple(step.semantic_sha256 for step in certification.batch_result.steps)
        or artifact.output_ids
        != tuple(target.target_id for target in certification.batch_result.targets)
    ):
        raise FixtureEconomicSegmentError(
            "economic execution changed the completed target transcript"
        )

    rows: list[FixtureEconomicRow] = []
    for step in certification.batch_result.steps:
        batch = step.source_feature_step.source_batch
        if not batch.complete:
            continue
        context = step.context
        if context is None or context.source_batch != batch:
            raise FixtureEconomicSegmentError("economic target step lacks exact causal context")
        target_by_instrument = (
            {}
            if step.target is None
            else {item.instrument_id: item for item in step.target.targets}
        )
        expected_ids = batch.watermark.expected_instrument_ids
        if step.status is FeatureTargetStepStatus.READY:
            if step.target is None or tuple(target_by_instrument) != expected_ids:
                raise FixtureEconomicSegmentError(
                    "ready economic step changed its complete target snapshot"
                )
        elif step.status is not FeatureTargetStepStatus.WAITING or step.target is not None:
            raise FixtureEconomicSegmentError("economic complete step has unsupported status")
        rows.append(
            FixtureEconomicRow(
                sequence=step.sequence,
                as_of=batch.as_of,
                source_batch_sha256=batch.semantic_sha256,
                target_id=None if step.target is None else step.target.target_id,
                instruments=tuple(
                    FixtureEconomicInstrumentInput(
                        instrument_id=instrument_id,
                        symbol=batch.event_for(instrument_id).symbol,
                        close_price=batch.event_for(instrument_id).close_price,
                        target_quantity=(
                            None
                            if step.target is None
                            else target_by_instrument[instrument_id].quantity
                        ),
                    )
                    for instrument_id in expected_ids
                ),
            )
        )
    return FixtureEconomicSegmentRequest(
        job_id=projection.job.job_id,
        family_id=projection.job.family_id,
        attempt_id=projection.job.attempt_id,
        configuration_sha256=projection.job.configuration_sha256,
        segment_kind=projection.job.segment_kind.value,
        segment_sha256=projection.job.segment_sha256,
        completion_receipt_sha256=projection.latest.completion_receipt_sha256,
        target_artifact_sha256=artifact.artifact_sha256,
        target_certification_sha256=certification.semantic_sha256,
        target_transcript_sha256=certification.batch_result.transcript_sha256,
        rows=tuple(rows),
    )


def evaluate_fixture_economic_request(
    request: FixtureEconomicSegmentRequest,
) -> FixtureEconomicSegmentResult:
    """Independently evaluate the closed immediate-fill fixture model."""

    if type(request) is not FixtureEconomicSegmentRequest:
        raise FixtureEconomicSegmentError("economic evaluation requires an exact request")
    request.__post_init__()
    first = request.rows[0]
    quantities = {item.instrument_id: Decimal(0) for item in first.instruments}
    symbols = {item.instrument_id: item.symbol for item in first.instruments}
    marks = {item.instrument_id: item.close_price for item in first.instruments}
    cash = request.starting_cash
    gross_notional = Decimal(0)
    trade_count = 0
    filled_target_count = 0
    for row in request.rows:
        marks = {item.instrument_id: item.close_price for item in row.instruments}
        if row.target_id is None:
            continue
        filled_target_count += 1
        for item in row.instruments:
            assert item.target_quantity is not None
            delta = exact_decimal_subtract(item.target_quantity, quantities[item.instrument_id])
            if delta == 0:
                continue
            notional = exact_decimal_multiply(delta, item.close_price)
            cash = exact_decimal_subtract(cash, notional)
            gross_notional = exact_decimal_add(gross_notional, notional.copy_abs())
            quantities[item.instrument_id] = item.target_quantity
            trade_count += 1
    positions = tuple(
        FixtureEconomicPosition(
            instrument_id=instrument_id,
            symbol=symbols[instrument_id],
            quantity=quantities[instrument_id],
            mark_price=marks[instrument_id],
            market_value=exact_decimal_multiply(
                quantities[instrument_id],
                marks[instrument_id],
            ),
        )
        for instrument_id in sorted(quantities)
    )
    market_value = exact_decimal_sum(tuple(position.market_value for position in positions))
    equity = exact_decimal_add(cash, market_value)
    return FixtureEconomicSegmentResult(
        request_sha256=request.semantic_sha256,
        ending_cash=cash,
        ending_market_value=market_value,
        ending_equity=equity,
        net_pnl=exact_decimal_subtract(equity, request.starting_cash),
        gross_traded_notional=gross_notional,
        trade_count=trade_count,
        filled_target_count=filled_target_count,
        positions=positions,
    )


def fixture_economic_decimal_text(value: Decimal) -> str:
    """Expose the contract's exact plain-protocol Decimal representation."""

    return canonical_decimal_text(_decimal(value, "economic protocol decimal"))


__all__ = [
    "FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS",
    "FIXTURE_ECONOMIC_CHILD_PROCESSES",
    "FIXTURE_ECONOMIC_CPU_SECONDS",
    "FIXTURE_ECONOMIC_FILE_BYTES",
    "FIXTURE_ECONOMIC_MODEL_VERSION",
    "FIXTURE_ECONOMIC_OPEN_FILES",
    "FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION",
    "FIXTURE_ECONOMIC_STARTING_CASH",
    "FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS",
    "MAX_FIXTURE_ECONOMIC_INSTRUMENTS",
    "MAX_FIXTURE_ECONOMIC_REQUEST_BYTES",
    "MAX_FIXTURE_ECONOMIC_ROWS",
    "MAX_FIXTURE_ECONOMIC_STDERR_BYTES",
    "MAX_FIXTURE_ECONOMIC_STDOUT_BYTES",
    "FixtureEconomicInstrumentInput",
    "FixtureEconomicPosition",
    "FixtureEconomicProcessEvidence",
    "FixtureEconomicProcessOutcome",
    "FixtureEconomicRow",
    "FixtureEconomicSegmentError",
    "FixtureEconomicSegmentReceipt",
    "FixtureEconomicSegmentRequest",
    "FixtureEconomicSegmentResult",
    "bind_fixture_economic_request",
    "evaluate_fixture_economic_request",
    "fixture_economic_decimal_text",
    "fixture_economic_isolation_profile_sha256",
]
