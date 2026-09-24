"""Bounded data equality for explicitly projected, owner-authenticated captures.

This supplies no ownership or financial validity. Persistence owners must select
every private field and authenticate opaque tokens themselves. No SQL expression,
capture dataclass, codec, digest or object-store operation is accepted here.
"""

from collections.abc import Iterator, Mapping
from dataclasses import fields
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from sys import modules
from types import MappingProxyType
from typing import Any, TypeVar, cast

from sqlalchemy.sql.elements import quoted_name

from packages.domain.account_coordinator import AccountFence
from packages.domain.account_projection import OpenTaxLot
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.decision import DecisionTrigger
from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    LedgerCashFlow,
)
from packages.domain.models import OrderIntent, PositionTarget
from packages.domain.order_reducer import BrokerOrderEvent, OrderCancelRequest, OrderSubmission
from packages.domain.personal_contracts import ContractRecord
from packages.domain.research_dataset import ResearchCalendar, ResearchSession
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
)
from packages.domain.wealth import WealthPoint

MAX_CAPTURE_COMPARISON_CONTAINERS = 16_384
MAX_CAPTURE_COMPARISON_BINDINGS = 131_072
T = TypeVar("T")

# Older domain data nested in the declared checkpoint/source annotation graph.
# This exact class list deliberately excludes persistence plans/captures/owners.
_LEGACY_RECORDS = (
    AccountFence,
    OpenTaxLot,
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
    ReferenceConfiguration,
    DecisionTrigger,
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    LedgerCashFlow,
    OrderIntent,
    PositionTarget,
    BrokerOrderEvent,
    OrderCancelRequest,
    OrderSubmission,
    ResearchCalendar,
    ResearchSession,
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
    WealthPoint,
)


class ContinuousCaptureComparisonError(ValueError):
    pass


class ContinuousCaptureComparison:
    """One comparison's cumulative, narrower data-profile limits.

    Repeated calls always reread their inputs. Within one data walk, aliases are
    visited once but each incoming binding is charged; cycles are rejected.
    A malformed self-referential enum is denied by the same finite counters.
    There is no cross-call validity cache or source registration.
    """

    def __init__(self) -> None:
        self.containers = 0
        self.bindings = 0

    def _charge(self, containers: int, bindings: int) -> None:
        if (
            self.containers + containers > MAX_CAPTURE_COMPARISON_CONTAINERS
            or self.bindings + bindings > MAX_CAPTURE_COMPARISON_BINDINGS
        ):
            raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_COMPARISON_BOUND")
        self.containers += containers
        self.bindings += bindings

    def identity(self, original: object, fresh: object) -> None:
        self._charge(0, 1)
        if original is not fresh:
            raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_IDENTITY_DIFFERS")

    def pairs(self, original: tuple[T, ...], fresh: tuple[T, ...]) -> Iterator[tuple[T, T]]:
        if type(original) is not tuple or type(fresh) is not tuple or len(original) != len(fresh):
            raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_TUPLE_DIFFERS")
        self._charge(1, len(original))
        return zip(original, fresh, strict=True)

    def data(self, original: object, fresh: object) -> None:
        self._charge(0, 1)
        pending: list[tuple[object, object, bool]] = [(original, fresh, False)]
        active: set[tuple[int, int]] = set()
        visited: set[tuple[int, int]] = set()
        while pending:
            left, right, leaving = pending.pop()
            pair = id(left), id(right)
            if leaving:
                active.remove(pair)
                visited.add(pair)
                continue
            kind = type(left)
            if kind is not type(right):
                raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DATA_TYPE_DIFFERS")
            if left is None or kind in (bool, int, str, bytes, date, timedelta):
                if left != right:
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DATA_DIFFERS")
                continue
            if kind is Decimal:
                if cast(Decimal, left).as_tuple() != cast(Decimal, right).as_tuple():
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DECIMAL_DIFFERS")
                continue
            if kind is datetime:
                a, b = cast(datetime, left), cast(datetime, right)
                if type(a.tzinfo) not in (type(None), timezone) or type(b.tzinfo) not in (
                    type(None),
                    timezone,
                ):
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_TIMEZONE_TYPE")
                if (
                    a.replace(tzinfo=None) != b.replace(tzinfo=None)
                    or a.fold != b.fold
                    or type(a.tzinfo) is not type(b.tzinfo)
                    or a.utcoffset() != b.utcoffset()
                    or a.tzname() != b.tzname()
                ):
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DATETIME_DIFFERS")
                continue
            if isinstance(left, Enum):
                if left is not right:
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_ENUM_DIFFERS")
                # Exact original enum member identity, with only admitted data below.
                self._charge(1, 2)
                pending.extend(
                    (
                        (left.name, right.name, False),
                        (left.value, right.value, False),
                    )
                )
                continue
            if pair in active:
                raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DATA_CYCLE")
            if pair in visited:
                continue
            children: Iterator[tuple[object, object]]
            if kind is tuple:
                a_tuple, b_tuple = cast(tuple[object, ...], left), cast(tuple[object, ...], right)
                if len(a_tuple) != len(b_tuple):
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_TUPLE_DIFFERS")
                self._charge(1, len(a_tuple))
                children = zip(a_tuple, b_tuple, strict=True)
            elif kind in (dict, MappingProxyType):
                a_map, b_map = (
                    cast(Mapping[object, object], left),
                    cast(Mapping[object, object], right),
                )
                if len(a_map) != len(b_map):
                    raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_ROW_DIFFERS")
                # Reserve key/value plus the possible exact SQL key quote flag
                # before allocating entries; ordinary str keys use this same cap.
                self._charge(1, 3 * len(a_map))
                entries = []
                for (ka, va), (kb, vb) in zip(a_map.items(), b_map.items(), strict=True):
                    key_type = type(ka)
                    if (
                        key_type is not type(kb)
                        or key_type not in (str, quoted_name)
                        or str.__eq__(cast(str, ka), cast(str, kb)) is not True
                    ):
                        raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_ROW_KEYS_DIFFER")
                    if key_type is quoted_name:
                        qa, qb = cast(quoted_name, ka).quote, cast(quoted_name, kb).quote
                        if not any(qa is flag for flag in (None, True, False)) or qa is not qb:
                            raise ContinuousCaptureComparisonError(
                                "COMPLETE_CAPTURE_ROW_QUOTE_DIFFERS"
                            )
                    entries.append((va, vb))
                children = iter(entries)
            elif kind in _LEGACY_RECORDS or (
                issubclass(kind, ContractRecord)
                and kind.__module__.startswith("packages.domain.")
                and vars(modules[kind.__module__]).get(kind.__name__) is kind
            ):
                self._charge(1, len(cast(Any, kind).__dataclass_fields__))
                definitions = fields(cast(Any, left))
                children = ((getattr(left, f.name), getattr(right, f.name)) for f in definitions)
            else:
                raise ContinuousCaptureComparisonError("COMPLETE_CAPTURE_DATA_PROFILE")
            active.add(pair)
            pending.append((left, right, True))
            pending.extend((a, b, False) for a, b in children)
