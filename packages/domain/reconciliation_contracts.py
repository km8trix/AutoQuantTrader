"""Immutable observed/applied reconciliation values; no execution authority.

These records never replace ledger projections, resolve UNKNOWN, release holds,
or re-arm an account. Producers and durable readers must authenticate references
and recompute application/comparison evidence before consumers rely on a result.
The historical non-applying reconciliation and inbox contracts remain unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import ClassVar, Literal

from packages.domain.models import Side
from packages.domain.personal_contracts import ContractRecord, require_amount, require_digest

RECONCILIATION_VERSION = "personal-applied-reconciliation/1"
MAX_RECONCILIATION_ITEMS = 4096
MAX_RECONCILIATION_PAGES = 256
MAX_RECONCILIATION_COUNTER = 2**63 - 1
type ReconciliationSourceClass = Literal["stateful_simulation", "provider_observation"]
type ReconciliationStatus = Literal["blocked", "pending_bounded_lag", "converged"]
type DiscrepancyCode = Literal[
    "EXPECTED_BOUNDED_LAG",
    "MISSING_EXECUTION",
    "DUPLICATE_OR_CONFLICT",
    "EXTERNAL_TRADE",
    "EXTERNAL_CASH_FLOW",
    "CORPORATE_ACTION",
    "UNKNOWN_ORDER",
    "UNSUPPORTED_ACTIVITY",
    "COVERAGE_GAP",
    "UNEXPLAINED_CASH_OR_POSITION",
]


def require_reconciliation_id(value: str, name: str) -> None:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise ValueError(f"invalid bounded {name}")


def _counter(value: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= MAX_RECONCILIATION_COUNTER:
        raise ValueError(f"invalid bounded {name}")


def _ids(values: tuple[str, ...], name: str) -> None:
    if type(values) is not tuple or len(values) > MAX_RECONCILIATION_ITEMS:
        raise ValueError(f"{name} exceeds its immutable item bound")
    for value in values:
        require_reconciliation_id(value, name)
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{name} requires sorted unique identifiers")


class ReconciliationRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = RECONCILIATION_VERSION


@dataclass(frozen=True, slots=True)
class ReconciliationScope(ReconciliationRecord):
    account_id: str
    provider_id: str
    environment: str
    binding_sha256: str
    source_class: ReconciliationSourceClass

    def __post_init__(self) -> None:
        super(ReconciliationScope, self).__post_init__()
        require_reconciliation_id(self.account_id, "account identity")
        require_reconciliation_id(self.provider_id, "provider identity")
        require_digest(self.binding_sha256, "account binding")
        permitted = (
            ("stateful_simulation",)
            if self.source_class == "stateful_simulation"
            else ("sandbox", "production")
        )
        if self.environment not in permitted:
            raise ValueError("source class and actual environment disagree")


@dataclass(frozen=True, slots=True)
class ReconciliationHeads(ReconciliationRecord):
    """Exact post-application transaction heads, not timestamp approximations.

    Ledger/order hashes are AccountSnapshot.journal_sha256/order_sha256. Capacity
    hashes the full durable hold inventory, including unresolved obligations.
    Effect watermark includes newer sends/attempt transitions; it is not a clock.
    """

    ledger_sha256: str
    order_sha256: str
    capacity_sha256: str
    effect_watermark: int
    attempt_sha256: str
    control_revision: int
    lease_generation: int

    def __post_init__(self) -> None:
        super(ReconciliationHeads, self).__post_init__()
        for name in ("ledger_sha256", "order_sha256", "capacity_sha256", "attempt_sha256"):
            require_digest(getattr(self, name), name)
        for name in ("effect_watermark", "control_revision", "lease_generation"):
            _counter(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class ReconciliationDiscrepancy(ReconciliationRecord):
    code: DiscrepancyCode
    subject: str
    reason: str
    expected: Decimal | None = None
    observed: Decimal | None = None
    evidence_ids: tuple[str, ...] = ()
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        super(ReconciliationDiscrepancy, self).__post_init__()
        require_reconciliation_id(self.subject, "discrepancy subject")
        require_reconciliation_id(self.reason, "discrepancy reason")
        _ids(self.evidence_ids, "discrepancy evidence")
        for name in ("expected", "observed"):
            value = getattr(self, name)
            if value is not None:
                require_amount(value, name)
        if (self.code == "EXPECTED_BOUNDED_LAG") != (self.expires_at is not None):
            raise ValueError("only explained bounded lag requires an explicit expiry")
        if self.code == "EXPECTED_BOUNDED_LAG" and not self.evidence_ids:
            raise ValueError("bounded lag requires named pending fact evidence")


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy(ReconciliationRecord):
    lookback_calendar_days: int = 7
    freshness_seconds: int = 60
    convergence_seconds: int = 120
    maximum_display_tolerance: Decimal = Decimal("0.01")

    def __post_init__(self) -> None:
        super(ReconciliationPolicy, self).__post_init__()
        if (self.lookback_calendar_days, self.freshness_seconds, self.convergence_seconds) != (
            7,
            60,
            120,
        ):
            raise ValueError("reconciliation timing differs from the frozen policy")
        if self.maximum_display_tolerance != Decimal("0.01"):
            raise ValueError("reconciliation tolerance differs from the frozen policy")


@dataclass(frozen=True, slots=True)
class ReconciliationResult(ReconciliationRecord):
    scope: ReconciliationScope
    heads: ReconciliationHeads
    round_sha256: str
    previous_result_sha256: str | None
    observation_started_at: datetime
    observation_received_through: datetime
    coverage_from: datetime | None
    coverage_through: datetime | None
    applied_through: datetime | None
    completed_at: datetime
    status: ReconciliationStatus
    blocking_reasons: tuple[str, ...]
    discrepancies: tuple[ReconciliationDiscrepancy, ...]
    applied_fact_ids: tuple[str, ...] = ()
    unresolved_fact_ids: tuple[str, ...] = ()
    quarantined_fact_ids: tuple[str, ...] = ()
    source_receipt_ids: tuple[str, ...] = ()
    policy_sha256: str = ReconciliationPolicy().semantic_sha256

    def __post_init__(self) -> None:
        super(ReconciliationResult, self).__post_init__()
        require_digest(self.round_sha256, "observation round")
        require_digest(self.policy_sha256, "reconciliation policy")
        if self.previous_result_sha256 is not None:
            require_digest(self.previous_result_sha256, "previous reconciliation result")
        for name in (
            "blocking_reasons",
            "applied_fact_ids",
            "unresolved_fact_ids",
            "quarantined_fact_ids",
            "source_receipt_ids",
        ):
            _ids(getattr(self, name), name)
        if len(self.discrepancies) > MAX_RECONCILIATION_ITEMS:
            raise ValueError("reconciliation discrepancies exceed item bound")
        fact_groups = (self.applied_fact_ids, self.unresolved_fact_ids, self.quarantined_fact_ids)
        if len(set().union(*map(set, fact_groups))) != sum(map(len, fact_groups)):
            raise ValueError("applied/unresolved/quarantined fact identities overlap")
        if (
            not self.observation_started_at
            <= self.observation_received_through
            <= self.completed_at
        ):
            raise ValueError("reconciliation receipt/completion times regress")
        if (self.coverage_from is None) != (self.coverage_through is None):
            raise ValueError("coverage requires both interval bounds or neither")
        if (
            self.coverage_from is not None
            and self.coverage_through is not None
            and not self.coverage_from <= self.coverage_through <= self.observation_received_through
        ):
            raise ValueError("coverage cannot extend beyond observed evidence")
        if self.applied_through is not None and self.applied_through > self.completed_at:
            raise ValueError("applied evidence cannot be in the future")
        if self.status == "converged":
            if (
                self.blocking_reasons
                or self.discrepancies
                or self.unresolved_fact_ids
                or self.quarantined_fact_ids
                or self.previous_result_sha256 is None
                or self.coverage_through is None
                or self.applied_through is None
                or not self.source_receipt_ids
            ):
                raise ValueError("convergence requires complete, explained repeated evidence")
        elif not self.blocking_reasons:
            raise ValueError("non-converged comparison requires explicit blocking reasons")
        if self.status == "pending_bounded_lag" and (
            not self.discrepancies
            or self.quarantined_fact_ids
            or any(
                item.code != "EXPECTED_BOUNDED_LAG"
                or item.expires_at is None
                or item.expires_at <= self.completed_at
                for item in self.discrepancies
            )
        ):
            raise ValueError("pending status requires only unexpired explained lag")


type ReconciliationOperation = Literal[
    "balances", "positions", "orders_current", "orders_history", "activity"
]
type CashField = Literal[
    "trade_date_cash",
    "settled_cash",
    "trade_receivable",
    "trade_payable",
    "dividend_receivable",
    "fees",
    "margin_liability",
    "restricted_cash",
]
REQUIRED_RECONCILIATION_OPERATIONS: tuple[ReconciliationOperation, ...] = (
    "balances",
    "positions",
    "orders_current",
    "orders_history",
    "activity",
)
REQUIRED_CASH_FIELDS: tuple[CashField, ...] = (
    "trade_date_cash",
    "settled_cash",
    "trade_receivable",
    "trade_payable",
    "dividend_receivable",
    "fees",
    "margin_liability",
    "restricted_cash",
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReconciliationPage(ReconciliationRecord):
    """One factual source page; termination describes evidence, not permission."""

    operation: ReconciliationOperation
    receipt_id: str
    scope_sha256: str
    query_sha256: str  # Common query without its continuation marker.
    request_sha256: str  # Exact request including its continuation marker.
    body_sha256: str
    body_bytes: int
    ordinal: int
    requested_at: datetime
    received_at: datetime
    requested_from: datetime | None
    requested_through: datetime | None
    cursor: str | None
    next_cursor: str | None
    termination: Literal["more", "documented_end", "no_content", "unknown"]
    terminal_evidence_sha256: str | None
    selection: Literal["all_account", "filtered", "unknown"]
    provider_sequence: int | None = None

    def __post_init__(self) -> None:
        super(ReconciliationPage, self).__post_init__()
        require_reconciliation_id(self.receipt_id, "page receipt")
        for name in ("scope_sha256", "query_sha256", "request_sha256", "body_sha256"):
            require_digest(getattr(self, name), name)
        if not 0 <= self.body_bytes <= 2 * 1024 * 1024:
            raise ValueError("page body exceeds the bounded read-response size")
        if not 0 <= self.ordinal < MAX_RECONCILIATION_PAGES:
            raise ValueError("page ordinal is outside the page bound")
        if self.requested_at > self.received_at:
            raise ValueError("page receipt precedes its request")
        if (self.requested_from is None) != (self.requested_through is None):
            raise ValueError("page history requires both query bounds or neither")
        if (
            self.requested_from is not None
            and self.requested_through is not None
            and self.requested_from > self.requested_through
        ):
            raise ValueError("page history interval is reversed")
        for name in ("cursor", "next_cursor"):
            value = getattr(self, name)
            if value is not None and (
                not value
                or len(value) > 2048
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError("page cursor requires bounded opaque non-control text")
        if self.terminal_evidence_sha256 is not None:
            require_digest(self.terminal_evidence_sha256, "terminal-page evidence")
        if self.provider_sequence is not None:
            _counter(self.provider_sequence, "provider page sequence")


@dataclass(frozen=True, slots=True)
class CashObservation(ReconciliationRecord):
    field: CashField
    value: Decimal | None
    currency: str | None
    semantics_sha256: str | None
    display_tolerance: Decimal = Decimal(0)
    rounding_evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        super(CashObservation, self).__post_init__()
        if self.value is not None:
            require_amount(self.value, "observed cash")
        if self.currency is not None and re.fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise ValueError("observed currency must be an explicit ISO-style code or null")
        if self.semantics_sha256 is not None:
            require_digest(self.semantics_sha256, "cash-field semantics")
        require_amount(self.display_tolerance, "cash display tolerance", nonnegative=True)
        if self.display_tolerance > Decimal("0.01"):
            raise ValueError("cash display tolerance exceeds one cent")
        if bool(self.display_tolerance) != (self.rounding_evidence_sha256 is not None):
            raise ValueError("nonzero display tolerance requires documented rounding evidence")
        if self.rounding_evidence_sha256 is not None:
            require_digest(self.rounding_evidence_sha256, "rounding evidence")


@dataclass(frozen=True, slots=True)
class PositionObservation(ReconciliationRecord):
    instrument_id: str | None
    symbol: str
    quantity: Decimal

    def __post_init__(self) -> None:
        super(PositionObservation, self).__post_init__()
        if self.instrument_id is not None:
            require_reconciliation_id(self.instrument_id, "position instrument")
        require_reconciliation_id(self.symbol, "position symbol")
        # Unsupported fractional/short observations are retained, then blocked.
        require_amount(self.quantity, "observed position quantity")


@dataclass(frozen=True, slots=True)
class OrderObservation(ReconciliationRecord):
    provider_order_id: str
    order_id: str | None
    instrument_id: str | None
    symbol: str
    side: Side | None
    quantity: Decimal | None
    filled_quantity: Decimal | None
    status: Literal[
        "working", "partial", "pending_cancel", "filled", "canceled", "rejected", "unknown"
    ]
    provider_sequence: int | None = None

    def __post_init__(self) -> None:
        super(OrderObservation, self).__post_init__()
        require_reconciliation_id(self.provider_order_id, "provider order")
        require_reconciliation_id(self.symbol, "order symbol")
        for name in ("order_id", "instrument_id"):
            value = getattr(self, name)
            if value is not None:
                require_reconciliation_id(value, name)
        for name in ("quantity", "filled_quantity"):
            value = getattr(self, name)
            if value is not None:
                require_amount(value, name)
        if self.provider_sequence is not None:
            _counter(self.provider_sequence, "provider order sequence")


@dataclass(frozen=True, slots=True)
class FactObservation(ReconciliationRecord):
    """Reference to exact canonical content, never a cumulative-fill conversion.

    The fact hash binds the existing order/ledger/action primitive. Receipt IDs
    identify this delivery separately, so a repeated observation is not a new
    execution. Actual payload admission/application belongs to the coordinator.
    """

    fact_id: str
    fact_sha256: str
    kind: Literal[
        "order",
        "execution",
        "correction",
        "cash_flow",
        "corporate_action",
        "settlement",
        "unsupported",
    ]
    provider_fact_id: str | None
    provider_revision: str | None
    provider_sequence: int | None
    source_receipt_id: str
    effective_at: datetime | None
    received_at: datetime
    origin: Literal["application", "external"] = "application"
    predecessor_fact_id: str | None = None

    def __post_init__(self) -> None:
        super(FactObservation, self).__post_init__()
        require_reconciliation_id(self.fact_id, "canonical fact identity")
        require_digest(self.fact_sha256, "canonical fact content")
        require_reconciliation_id(self.source_receipt_id, "fact receipt")
        for name in ("provider_fact_id", "provider_revision", "predecessor_fact_id"):
            value = getattr(self, name)
            if value is not None:
                require_reconciliation_id(value, name)
        if self.provider_sequence is not None:
            _counter(self.provider_sequence, "provider fact sequence")
        if self.effective_at is not None and self.effective_at > self.received_at:
            raise ValueError("fact receipt precedes its effective time")
        if self.predecessor_fact_id == self.fact_id:
            raise ValueError("fact cannot supersede itself")


@dataclass(frozen=True, slots=True)
class FactApplication(ReconciliationRecord):
    fact_id: str
    fact_sha256: str
    applied_at: datetime
    journal_entry_ids: tuple[str, ...] = ()
    order_event_ids: tuple[str, ...] = ()
    canonical_fact_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(FactApplication, self).__post_init__()
        require_reconciliation_id(self.fact_id, "applied fact")
        require_digest(self.fact_sha256, "applied content")
        _ids(self.journal_entry_ids, "journal application links")
        _ids(self.order_event_ids, "order application links")
        _ids(self.canonical_fact_ids, "retained canonical fact links")
        if not self.journal_entry_ids and not self.order_event_ids and not self.canonical_fact_ids:
            raise ValueError("applied fact requires actual canonical history links")


@dataclass(frozen=True, slots=True)
class ReconciliationObligation(ReconciliationRecord):
    """Identity-only view of a durable hold; amounts stay with B's inventory."""

    order_id: str
    provider_order_id: str | None
    state: Literal[
        "approved_unsent", "working", "partial", "unknown", "pending_cancel", "terminal_unreleased"
    ]
    source_sha256: str

    def __post_init__(self) -> None:
        super(ReconciliationObligation, self).__post_init__()
        require_reconciliation_id(self.order_id, "obligation order")
        if self.provider_order_id is not None:
            require_reconciliation_id(self.provider_order_id, "obligation provider order")
        require_digest(self.source_sha256, "durable obligation source")


@dataclass(frozen=True, slots=True)
class ReconciliationOrderBinding(ReconciliationRecord):
    """Retained authoritative identity mapping, including released old orders."""

    order_id: str
    provider_order_id: str
    source_sha256: str

    def __post_init__(self) -> None:
        super(ReconciliationOrderBinding, self).__post_init__()
        require_reconciliation_id(self.order_id, "mapped local order")
        require_reconciliation_id(self.provider_order_id, "mapped provider order")
        require_digest(self.source_sha256, "order identity evidence")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationRound(ReconciliationRecord):
    scope: ReconciliationScope
    round_id: str
    started_at: datetime
    completed_at: datetime
    requested_from: datetime
    requested_through: datetime
    pages: tuple[ReconciliationPage, ...]
    cash: tuple[CashObservation, ...]
    positions: tuple[PositionObservation, ...]
    orders: tuple[OrderObservation, ...]
    facts: tuple[FactObservation, ...]
    currency: str | None
    account_modes: tuple[tuple[str, str | None], ...]
    source_blockers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(ObservationRound, self).__post_init__()
        require_reconciliation_id(self.round_id, "observation round")
        if self.started_at > self.completed_at or self.requested_from > self.requested_through:
            raise ValueError("observation/query interval is reversed")
        if len(self.pages) > MAX_RECONCILIATION_PAGES:
            raise ValueError("observation exceeds its page bound")
        if any(
            len(values) > MAX_RECONCILIATION_ITEMS
            for values in (self.cash, self.positions, self.orders, self.facts)
        ):
            raise ValueError("observation exceeds its item bound")
        if self.currency is not None and re.fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise ValueError("account currency must be explicit or null")
        if len(self.account_modes) > 8:
            raise ValueError("account-mode source inventory exceeds its bound")
        sources = tuple(source for source, _ in self.account_modes)
        _ids(sources, "account-mode sources")
        for _, mode in self.account_modes:
            if mode is not None:
                require_reconciliation_id(mode, "observed account mode")
        _ids(self.source_blockers, "source blockers")


@dataclass(frozen=True, slots=True)
class CoverageAssessment(ReconciliationRecord):
    coverage_from: datetime | None
    coverage_through: datetime | None
    source_receipt_ids: tuple[str, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        super(CoverageAssessment, self).__post_init__()
        _ids(self.source_receipt_ids, "coverage receipts")
        _ids(self.reasons, "coverage reasons")
        if (self.coverage_from is None) != (self.coverage_through is None):
            raise ValueError("coverage interval must have both bounds")
        if (
            self.coverage_from is not None
            and self.coverage_through is not None
            and self.coverage_from > self.coverage_through
        ):
            raise ValueError("coverage interval is reversed")
