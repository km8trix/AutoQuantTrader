"""Immutable, explicitly chained state carried between strategy callbacks."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType

from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.decision import DecisionTrigger

STRATEGY_STATE_CONTRACT_VERSION = "phase2-strategy-state-v1"
MAX_STATE_FIELDS = 128
MAX_STATE_KEY_LENGTH = 128
MAX_STATE_STRING_LENGTH = 4096
MAX_STATE_PAYLOAD_BYTES = 65_536
MAX_STATE_INTEGER_BITS = 256

type StrategyStateValue = None | bool | int | str | Decimal | datetime


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _normalize_value(value: object) -> StrategyStateValue:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > MAX_STATE_INTEGER_BITS:
            raise ValueError("strategy state integer exceeds its size limit")
        return value
    if type(value) is str:
        if len(value) > MAX_STATE_STRING_LENGTH:
            raise ValueError("strategy state string exceeds its size limit")
        return value
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("strategy state Decimal must be finite")
        return canonical_decimal(value)
    if type(value) is datetime:
        _require_utc(value, "strategy state datetime")
        return value
    raise ValueError("strategy state values must be null, bool, int, str, Decimal, or UTC datetime")


@dataclass(frozen=True, slots=True, init=False)
class VersionedStrategyState:
    """A bounded canonical payload linked to its exact predecessor and trigger."""

    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    schema_version: str
    generation: int
    as_of: datetime
    previous_state_sha256: str | None
    trigger: DecisionTrigger | None
    _values: tuple[tuple[str, StrategyStateValue], ...]

    def __init__(
        self,
        *,
        strategy_id: str,
        strategy_version: str,
        strategy_configuration_sha256: str,
        schema_version: str,
        generation: int,
        as_of: datetime,
        values: Mapping[str, object],
        previous_state_sha256: str | None = None,
        trigger: DecisionTrigger | None = None,
    ) -> None:
        for identity_value, field_name in (
            (strategy_id, "strategy state strategy_id"),
            (strategy_version, "strategy state strategy_version"),
            (schema_version, "strategy state schema_version"),
        ):
            _require_text(identity_value, field_name)
        _require_sha256(
            strategy_configuration_sha256,
            "strategy state configuration digest",
        )
        if type(generation) is not int or generation < 0:
            raise ValueError("strategy state generation must be a non-negative integer")
        _require_utc(as_of, "strategy state as_of")
        if not isinstance(values, Mapping):
            raise ValueError("strategy state values must be a mapping")
        if len(values) > MAX_STATE_FIELDS:
            raise ValueError("strategy state exceeds its field-count limit")

        normalized: list[tuple[str, StrategyStateValue]] = []
        for key, state_value in values.items():
            _require_text(key, "strategy state key")
            if len(key) > MAX_STATE_KEY_LENGTH:
                raise ValueError("strategy state key exceeds its size limit")
            normalized.append((key, _normalize_value(state_value)))
        normalized_values = tuple(sorted(normalized))
        if len({key for key, _ in normalized_values}) != len(normalized_values):
            raise ValueError("strategy state keys must be unique")
        if len(canonical_json_bytes(normalized_values)) > MAX_STATE_PAYLOAD_BYTES:
            raise ValueError("strategy state exceeds its encoded payload limit")

        if generation == 0:
            if previous_state_sha256 is not None or trigger is not None:
                raise ValueError("initial strategy state cannot have a predecessor or trigger")
        else:
            if previous_state_sha256 is None:
                raise ValueError("successor strategy state requires its predecessor digest")
            _require_sha256(previous_state_sha256, "strategy state predecessor digest")
            if type(trigger) is not DecisionTrigger:
                raise ValueError("successor strategy state requires an exact decision trigger")
            if as_of != trigger.as_of:
                raise ValueError("successor strategy state and trigger must share the same as_of")

        object.__setattr__(self, "strategy_id", strategy_id)
        object.__setattr__(self, "strategy_version", strategy_version)
        object.__setattr__(
            self,
            "strategy_configuration_sha256",
            strategy_configuration_sha256,
        )
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "as_of", as_of)
        object.__setattr__(self, "previous_state_sha256", previous_state_sha256)
        object.__setattr__(self, "trigger", trigger)
        object.__setattr__(self, "_values", normalized_values)

    @classmethod
    def initial(
        cls,
        *,
        strategy_id: str,
        strategy_version: str,
        strategy_configuration_sha256: str,
        schema_version: str,
        as_of: datetime,
        values: Mapping[str, object],
    ) -> VersionedStrategyState:
        return cls(
            strategy_id=strategy_id,
            strategy_version=strategy_version,
            strategy_configuration_sha256=strategy_configuration_sha256,
            schema_version=schema_version,
            generation=0,
            as_of=as_of,
            values=values,
        )

    @property
    def values(self) -> Mapping[str, StrategyStateValue]:
        return MappingProxyType(dict(self._values))

    @property
    def semantic_sha256(self) -> str:
        trigger_material = None
        if self.trigger is not None:
            trigger_material = self.trigger.semantic_sha256
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    STRATEGY_STATE_CONTRACT_VERSION,
                    self.strategy_id,
                    self.strategy_version,
                    self.strategy_configuration_sha256,
                    self.schema_version,
                    self.generation,
                    self.as_of,
                    self.previous_state_sha256,
                    trigger_material,
                    self._values,
                )
            )
        ).hexdigest()

    def advance(
        self,
        *,
        trigger: DecisionTrigger,
        values: Mapping[str, object],
    ) -> VersionedStrategyState:
        if trigger.as_of < self.as_of:
            raise ValueError("strategy state cannot move backwards in time")
        return VersionedStrategyState(
            strategy_id=self.strategy_id,
            strategy_version=self.strategy_version,
            strategy_configuration_sha256=self.strategy_configuration_sha256,
            schema_version=self.schema_version,
            generation=self.generation + 1,
            as_of=trigger.as_of,
            values=values,
            previous_state_sha256=self.semantic_sha256,
            trigger=trigger,
        )

    def require_successor(
        self,
        successor: VersionedStrategyState,
        trigger: DecisionTrigger,
    ) -> None:
        if type(successor) is not VersionedStrategyState:
            raise ValueError("strategy callback must return an exact versioned state")
        if successor.strategy_id != self.strategy_id:
            raise ValueError("strategy state changed strategy identity")
        if successor.strategy_version != self.strategy_version:
            raise ValueError("strategy state changed strategy version")
        if successor.strategy_configuration_sha256 != self.strategy_configuration_sha256:
            raise ValueError("strategy state changed strategy configuration")
        if successor.schema_version != self.schema_version:
            raise ValueError("strategy state changed schema version without migration")
        if successor.generation != self.generation + 1:
            raise ValueError("strategy state generation must advance exactly once")
        if successor.previous_state_sha256 != self.semantic_sha256:
            raise ValueError("strategy state does not chain to its exact predecessor")
        if successor.trigger != trigger:
            raise ValueError("strategy state is not bound to the exact callback trigger")
        if successor.as_of != trigger.as_of:
            raise ValueError("strategy state is not bound to the callback time")
