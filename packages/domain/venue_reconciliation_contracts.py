"""Scoped modeled-venue observations; identity references confer no authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.durable_journal_contracts import JournalHead
from packages.domain.order_reducer import OrderSubmission
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_application_contracts import ReconciliationFactCommand
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    MAX_RECONCILIATION_PAGES,
    CashObservation,
    ObservationRound,
    OrderObservation,
    PositionObservation,
    ReconciliationOperation,
    ReconciliationScope,
    require_reconciliation_id,
)
from packages.domain.reconciliation_persistence_contracts import ReconciliationSourceManifest
from packages.domain.stateful_venue_contracts import VenueFactPage, VenueModel

VENUE_CAPTURE_SCHEMA = "venue-reconciliation-page/1"


class VenueCaptureRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-venue-reconciliation/1"


@dataclass(frozen=True, slots=True)
class VenueSubmissionBinding(VenueCaptureRecord):
    submission: OrderSubmission
    registration_sha256: str
    provider_order_id: str

    def __post_init__(self) -> None:
        super(VenueSubmissionBinding, self).__post_init__()
        require_digest(self.registration_sha256, "venue registration")
        require_reconciliation_id(self.provider_order_id, "venue order identity")


@dataclass(frozen=True, slots=True)
class VenueAccountBinding(VenueCaptureRecord):
    scope: ReconciliationScope
    model: VenueModel
    source_sha256: str
    orders: tuple[VenueSubmissionBinding, ...]

    def __post_init__(self) -> None:
        super(VenueAccountBinding, self).__post_init__()
        require_digest(self.source_sha256, "account mapping evidence")
        if (
            self.scope.source_class != "stateful_simulation"
            or self.scope.provider_id != self.model.venue_id
        ):
            raise ValueError("VENUE_CAPTURE_SCOPE_DIFFERS")
        ids = tuple(value.submission.order_id for value in self.orders)
        if len(ids) > MAX_RECONCILIATION_ITEMS or ids != tuple(sorted(set(ids))):
            raise ValueError("VENUE_MAPPING_INVENTORY_INVALID")
        if len({value.provider_order_id for value in self.orders}) != len(ids):
            raise ValueError("VENUE_MAPPING_PROVIDER_DUPLICATE")


@dataclass(frozen=True, slots=True)
class VenueCaptureRequest(VenueCaptureRecord):
    capture_id: str
    binding: VenueAccountBinding
    requested_from: datetime
    requested_through: datetime
    through_head: JournalHead | None = None

    def __post_init__(self) -> None:
        super(VenueCaptureRequest, self).__post_init__()
        require_reconciliation_id(self.capture_id, "venue capture")
        if self.requested_from > self.requested_through:
            raise ValueError("VENUE_CAPTURE_INTERVAL_REVERSED")


@dataclass(frozen=True, slots=True)
class VenueFinancialPage(VenueCaptureRecord):
    operation: ReconciliationOperation
    ordinal: int
    offset: int
    next_offset: int
    complete: bool
    cash: tuple[CashObservation, ...] = ()
    positions: tuple[PositionObservation, ...] = ()
    orders: tuple[OrderObservation, ...] = ()
    fact_page: VenueFactPage | None = None
    action_predecessors: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        super(VenueFinancialPage, self).__post_init__()
        if not 0 <= self.ordinal < MAX_RECONCILIATION_PAGES:
            raise ValueError("VENUE_PAGE_ORDINAL_INVALID")
        if not 0 <= self.offset <= self.next_offset <= MAX_RECONCILIATION_ITEMS:
            raise ValueError("VENUE_PAGE_OFFSET_INVALID")
        if any(len(values) > 200 for values in (self.cash, self.positions, self.orders)):
            raise ValueError("VENUE_PAGE_ITEMS_EXCEEDED")
        if (
            (self.cash and self.operation != "balances")
            or (self.positions and self.operation != "positions")
            or (self.orders and self.operation not in ("orders_current", "orders_history"))
            or (self.fact_page is not None) != (self.operation == "activity")
        ):
            raise ValueError("VENUE_PAGE_CONTENT_ROLE_DIFFERS")
        dependency_ids = tuple(identity for identity, _ in self.action_predecessors)
        if dependency_ids != tuple(sorted(set(dependency_ids))) or len(dependency_ids) > 200:
            raise ValueError("VENUE_ACTION_DEPENDENCY_INVENTORY_INVALID")
        fact_ids = set() if self.fact_page is None else {f.fact_id for f in self.fact_page.facts}
        for identity, parents in self.action_predecessors:
            if (
                identity not in fact_ids
                or len(parents) > 16
                or parents != tuple(sorted(set(parents)))
                or identity in parents
            ):
                raise ValueError("VENUE_ACTION_DEPENDENCIES_INVALID")
            for parent in parents:
                require_reconciliation_id(parent, "venue action predecessor")
        if self.fact_page is not None:
            count = len(self.fact_page.facts)
            if (self.offset, self.next_offset, self.complete) != (
                self.fact_page.offset,
                self.fact_page.next_offset,
                self.fact_page.complete,
            ):
                raise ValueError("VENUE_FACT_PAGE_CURSOR_DIFFERS")
        else:
            count = len(self.cash) + len(self.positions) + len(self.orders)
        if self.next_offset != self.offset + count or (not self.complete and count == 0):
            raise ValueError("VENUE_PAGE_PROGRESS_INVALID")


@dataclass(frozen=True, slots=True)
class VenueCapturePage(VenueCaptureRecord):
    request: VenueCaptureRequest
    venue_head: JournalHead
    venue_state_sha256: str
    venue_as_of: datetime
    requested_at: datetime
    received_at: datetime
    body: VenueFinancialPage
    index: int
    page_count: int
    source_blockers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(VenueCapturePage, self).__post_init__()
        require_digest(self.venue_state_sha256, "venue source state")
        if not 0 <= self.index < self.page_count <= MAX_RECONCILIATION_PAGES:
            raise ValueError("VENUE_CAPTURE_PAGE_COUNT_INVALID")
        if (
            self.requested_at > self.received_at
            or self.venue_as_of > self.received_at
            or self.request.requested_through > self.requested_at
            or (
                self.request.through_head is not None
                and self.request.through_head != self.venue_head
            )
        ):
            raise ValueError("VENUE_CAPTURE_TIME_OR_HEAD_INVALID")
        if self.source_blockers != tuple(sorted(set(self.source_blockers))):
            raise ValueError("VENUE_CAPTURE_BLOCKERS_INVALID")
        for value in self.source_blockers:
            require_reconciliation_id(value, "venue capture blocker")
        fact_page = self.body.fact_page
        if fact_page is not None and (
            fact_page.state_sha256 != self.venue_state_sha256
            or fact_page.model_sha256 != self.request.binding.model.semantic_sha256
            or fact_page.through_sequence + 1 != self.venue_head.sequence
        ):
            raise ValueError("VENUE_CAPTURE_FACT_HEAD_DIFFERS")


@dataclass(frozen=True, slots=True)
class RetainedVenueCapture(VenueCaptureRecord):
    manifest: ReconciliationSourceManifest
    observed: ObservationRound
    facts: tuple[ReconciliationFactCommand, ...]
    source_order: tuple[str, ...]

    def __post_init__(self) -> None:
        super(RetainedVenueCapture, self).__post_init__()
        if self.manifest.scope != self.observed.scope or len(self.facts) > MAX_RECONCILIATION_ITEMS:
            raise ValueError("VENUE_CAPTURE_RESULT_INVALID")
        if len(self.source_order) != len(set(self.source_order)) or set(self.source_order) != {
            value.observation.fact_id for value in self.facts
        }:
            raise ValueError("VENUE_CAPTURE_SOURCE_ORDER_INVENTORY_DIFFERS")
        if sorted(value.page_receipt_id for value in self.manifest.sources) != sorted(
            page.receipt_id for page in self.observed.pages
        ) or sorted(value.observation.semantic_sha256 for value in self.facts) != sorted(
            value.semantic_sha256 for value in self.observed.facts
        ):
            raise ValueError("VENUE_CAPTURE_RESULT_CLOSURE_DIFFERS")
