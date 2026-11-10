"""Retained continuous C/B metadata, without history or execution authority.

These values describe row integrity at one SQL snapshot. They do not establish
owner authentication, checkpoint replay, readiness, clock health, account equity,
or permission to create exposure. Recorded model times are never retimed.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from packages.domain.personal_contracts import require_digest, require_utc


def _text(value: str, maximum: int) -> None:
    if type(value) is not str or not value or value != value.strip() or len(value) > maximum:
        raise ValueError("continuous selection metadata text is invalid")


def _counter(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ValueError("continuous selection metadata counter is outside native bounds")


@dataclass(frozen=True, slots=True)
class ContinuousSelectionCheckpoint:
    stream_id: str
    sequence: int
    recorded_at: datetime

    def __post_init__(self) -> None:
        _text(self.stream_id, 128)
        _counter(self.sequence)
        require_utc(self.recorded_at, "retained continuous checkpoint time")


@dataclass(frozen=True, slots=True)
class RetainedContinuousSelection:
    generation: int
    strategy_name: str
    strategy_version: str
    configuration_sha256: str
    instrument_symbols: tuple[tuple[str, str], ...]
    policy_id: str
    enabled_for_new_exposure: bool
    live_authorized: Literal[False]
    recorded_at: datetime
    effective_at: datetime

    def __post_init__(self) -> None:
        _counter(self.generation)
        for value in (self.strategy_name, self.strategy_version, self.policy_id):
            _text(value, 2048)
        require_digest(self.configuration_sha256, "retained selection configuration")
        if type(self.instrument_symbols) is not tuple or not 1 <= len(self.instrument_symbols) <= 4:
            raise ValueError("retained selection instrument inventory is invalid")
        for item in self.instrument_symbols:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("retained selection instrument pair is invalid")
            instrument, symbol = item
            _text(instrument, 2048)
            if type(symbol) is not str or symbol not in ("DIA", "IWM", "QQQ", "SPY"):
                raise ValueError("retained selection symbol is unsupported")
        instruments = tuple(item[0] for item in self.instrument_symbols)
        symbols = tuple(item[1] for item in self.instrument_symbols)
        if instruments != tuple(sorted(set(instruments))) or len(set(symbols)) != len(symbols):
            raise ValueError("retained selection instruments must be sorted and distinct")
        if type(self.enabled_for_new_exposure) is not bool or self.live_authorized is not False:
            raise ValueError("retained selection flags are invalid")
        require_utc(self.recorded_at, "retained selection recording time")
        require_utc(self.effective_at, "retained selection effective time")


@dataclass(frozen=True, slots=True)
class ContinuousSelectionSnapshot:
    account_id: str
    state: Literal["absent", "unselected", "selected"]
    checkpoint: ContinuousSelectionCheckpoint | None
    selection: RetainedContinuousSelection | None
    verification: Literal["row_integrity_only"] = "row_integrity_only"

    def __post_init__(self) -> None:
        _text(self.account_id, 128)
        if self.verification != "row_integrity_only" or type(self.verification) is not str:
            raise ValueError("continuous selection verification scope is invalid")
        if self.checkpoint is not None:
            if type(self.checkpoint) is not ContinuousSelectionCheckpoint:
                raise ValueError("continuous checkpoint metadata type is invalid")
            self.checkpoint.__post_init__()
        if self.selection is not None:
            if type(self.selection) is not RetainedContinuousSelection:
                raise ValueError("retained selection metadata type is invalid")
            self.selection.__post_init__()
        expected = (
            "absent"
            if self.checkpoint is None
            else "unselected"
            if self.selection is None
            else "selected"
        )
        _text(self.state, 10)
        if self.state != expected or (self.checkpoint is None and self.selection is not None):
            raise ValueError("continuous selection snapshot state is inconsistent")
