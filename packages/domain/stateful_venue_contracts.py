"""Independent simulated venue records; no provider or live execution authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import ClassVar, Literal, Protocol

from packages.domain.accounting_contracts import (
    AccountingState,
    ExecutionPolicy,
    RegisterVenueSubmission,
)
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.durable_journal_contracts import (
    JournalHead,
    JournalReceipt,
    journal_identifier,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardObservation, ForwardSource
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow
from packages.domain.order_reducer import BrokerOrderEvent
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    require_amount,
    require_digest,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
)

MAX_VENUE_COMMANDS = 4096
MAX_VENUE_FACTS = 16384
MAX_VENUE_OBJECT_BYTES = 16 * 1024 * 1024
MAX_VENUE_COMMAND_BYTES = 256 * 1024
MAX_VENUE_EFFECTS = 64


class VenueRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-stateful-venue/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class VenueModel(VenueRecord):
    account_id: str
    venue_id: str
    producer: VersionPin
    instruments: tuple[tuple[str, str], ...]
    sources: tuple[ForwardSource, ...]
    source_mode: Literal["synthetic_fixture", "recorded_as_observed"]
    execution_policy: ExecutionPolicy
    initial_cash_flow: LedgerCashFlow
    runtime_environment: Literal["stateful_simulation"] = "stateful_simulation"
    fact_source_class: Literal["stateful_simulation"] = "stateful_simulation"
    quote_policy: Literal["later-bid-ask-shared-costs/1"] = "later-bid-ask-shared-costs/1"
    liquidity_policy: Literal["explicit-whole-share-budget/1"] = "explicit-whole-share-budget/1"
    settlement_schedule: Literal["dated-us-equity-standard-settlement-v1"] = (
        "dated-us-equity-standard-settlement-v1"
    )
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(VenueModel, self).__post_init__()
        journal_identifier(self.account_id)
        journal_identifier(self.venue_id)
        if self.execution_policy.model_id != "stateful-venue-facts-v1":
            raise ValueError("venue requires its explicit observed-only accounting policy")
        if not 1 <= len(self.instruments) <= 4 or len(dict(self.instruments)) != len(
            self.instruments
        ):
            raise ValueError("venue requires 1..4 unique instruments")
        if len({s for _, s in self.instruments}) != len(self.instruments):
            raise ValueError("venue symbols must be unique")
        for instrument, symbol in self.instruments:
            journal_identifier(instrument)
            if symbol not in ("DIA", "IWM", "QQQ", "SPY"):
                raise ValueError("venue instrument is outside the personal universe")
        if not 1 <= len(self.sources) <= 4 or len({s.source_id for s in self.sources}) != len(
            self.sources
        ):
            raise ValueError("venue requires 1..4 unique pinned sources")
        if any(
            (s.provider == "fixture") != (self.source_mode == "synthetic_fixture")
            for s in self.sources
        ):
            raise ValueError("fixture and recorded source modes must remain distinct")
        if (
            self.initial_cash_flow.kind is not CashFlowKind.CONTRIBUTION
            or self.initial_cash_flow.currency != "USD"
        ):
            raise ValueError("venue genesis requires its own explicit USD contribution")


@dataclass(frozen=True, slots=True)
class VenueSourceReference(VenueRecord):
    producer: VersionPin
    semantic_sha256_ref: str
    object_ref: ObjectRef

    def __post_init__(self) -> None:
        super(VenueSourceReference, self).__post_init__()
        require_digest(self.semantic_sha256_ref, "source record")
        if self.object_ref.byte_count > MAX_VENUE_COMMAND_BYTES:
            raise ValueError("outbound source record exceeds its bound")


@dataclass(frozen=True, slots=True)
class VenueSubmit(VenueRecord):
    registration: RegisterVenueSubmission
    risk_source: VenueSourceReference
    dispatch_source: VenueSourceReference

    def __post_init__(self) -> None:
        super(VenueSubmit, self).__post_init__()
        if (
            self.registration.source_risk_admission_sha256 != self.risk_source.semantic_sha256_ref
            or self.registration.source_dispatch_sha256 != self.dispatch_source.semantic_sha256_ref
        ):
            raise ValueError("venue submission source references differ")


@dataclass(frozen=True, slots=True)
class VenueAccept(VenueRecord):
    order_id: str

    def __post_init__(self) -> None:
        super(VenueAccept, self).__post_init__()
        journal_identifier(self.order_id)


@dataclass(frozen=True, slots=True)
class VenueReject(VenueRecord):
    """An explicit modeled order rejection after registration, before acceptance."""

    order_id: str
    reason: str

    def __post_init__(self) -> None:
        super(VenueReject, self).__post_init__()
        journal_identifier(self.order_id)
        journal_identifier(self.reason)


@dataclass(frozen=True, slots=True)
class VenueCancel(VenueRecord):
    order_id: str
    reason: str

    def __post_init__(self) -> None:
        super(VenueCancel, self).__post_init__()
        journal_identifier(self.order_id)
        journal_identifier(self.reason)


@dataclass(frozen=True, slots=True)
class VenueQuote(VenueRecord):
    observation: ForwardObservation
    boot_id: str
    evaluated_monotonic_ns: int
    quantity_budget: Decimal

    def __post_init__(self) -> None:
        super(VenueQuote, self).__post_init__()
        journal_identifier(self.boot_id)
        if not 0 <= self.evaluated_monotonic_ns < 2**63:
            raise ValueError("venue monotonic time is outside its range")
        require_amount(self.quantity_budget, "modeled liquidity", nonnegative=True, whole=True)


@dataclass(frozen=True, slots=True)
class VenueCorrect(VenueRecord):
    execution_id: str
    quantity: Decimal
    price: Decimal
    fee: Decimal
    reason: str

    def __post_init__(self) -> None:
        super(VenueCorrect, self).__post_init__()
        journal_identifier(self.execution_id)
        journal_identifier(self.reason)
        require_amount(self.quantity, "corrected quantity", nonnegative=True, whole=True)
        require_amount(self.price, "corrected price", positive=True)
        require_amount(self.fee, "corrected fee", nonnegative=True)


@dataclass(frozen=True, slots=True)
class VenueRunDue(VenueRecord):
    limit: int = 32

    def __post_init__(self) -> None:
        super(VenueRunDue, self).__post_init__()
        if not 1 <= self.limit <= 32:
            raise ValueError("due settlement batch must contain at most 32 facts")


type VenueAction = LedgerCashFlow | StockSplitAction | CashDividendAccrual | CashDividendPayment
type VenuePayload = (
    VenueSubmit
    | VenueAccept
    | VenueReject
    | VenueCancel
    | VenueQuote
    | VenueCorrect
    | VenueRunDue
    | VenueAction
)
type VenueFactPayload = (
    BrokerOrderEvent
    | VenueAction
    | ExecutionSettlementInstruction
    | ExecutionSettlementConfirmation
)


@dataclass(frozen=True, slots=True)
class VenueCommand(VenueRecord):
    command_id: str
    received_at: datetime
    payload: VenuePayload

    def __post_init__(self) -> None:
        super(VenueCommand, self).__post_init__()
        journal_identifier(self.command_id)


@dataclass(frozen=True, slots=True)
class VenueFact(VenueRecord):
    fact_id: str
    command_id: str
    sequence: int
    payload: VenueFactPayload
    journal_entry_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        super(VenueFact, self).__post_init__()
        journal_identifier(self.fact_id)
        journal_identifier(self.command_id)
        if not 0 <= self.sequence <= MAX_VENUE_COMMANDS:
            raise ValueError("venue fact sequence is outside its bound")
        if len(self.journal_entry_ids) > 8 or len(set(self.journal_entry_ids)) != len(
            self.journal_entry_ids
        ):
            raise ValueError("venue fact posting references are invalid")


@dataclass(frozen=True, slots=True)
class VenueAck(VenueRecord):
    command_id: str
    command_sha256: str
    sequence: int
    disposition: Literal["registered", "applied", "rejected", "no_effect"]
    venue_order_id: str | None
    canonical_fact_ids: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(VenueAck, self).__post_init__()
        journal_identifier(self.command_id)
        require_digest(self.command_sha256, "venue command")
        if (
            not 1 <= self.sequence <= MAX_VENUE_COMMANDS
            or len(self.canonical_fact_ids) > MAX_VENUE_EFFECTS
        ):
            raise ValueError("venue acknowledgment is outside its bound")
        if self.disposition == "rejected" and not self.reasons:
            raise ValueError("rejected venue acknowledgment needs reasons")
        if self.venue_order_id is not None:
            journal_identifier(self.venue_order_id)
        if len(set(self.canonical_fact_ids)) != len(self.canonical_fact_ids):
            raise ValueError("venue acknowledgment repeats a fact")
        for identity in self.canonical_fact_ids:
            journal_identifier(identity)


@dataclass(frozen=True, slots=True)
class VenueDue(VenueRecord):
    instruction_id: str
    due_at: datetime

    def __post_init__(self) -> None:
        super(VenueDue, self).__post_init__()
        journal_identifier(self.instruction_id)


@dataclass(frozen=True, slots=True)
class VenueState(VenueRecord):
    model_sha256: str
    accounting: AccountingState
    sequence: int
    as_of: datetime
    commands: tuple[VenueCommand, ...]
    acknowledgments: tuple[VenueAck, ...]
    facts: tuple[VenueFact, ...]
    due_settlements: tuple[VenueDue, ...]
    forward_data: ForwardDataState

    def __post_init__(self) -> None:
        super(VenueState, self).__post_init__()
        require_digest(self.model_sha256, "venue model")
        if (
            not 0 <= self.sequence <= MAX_VENUE_COMMANDS
            or self.sequence != len(self.commands)
            or self.sequence != len(self.acknowledgments)
        ):
            raise ValueError("venue command inventory differs from its sequence")
        if (
            len({c.command_id for c in self.commands}) != self.sequence
            or len(self.facts) > MAX_VENUE_FACTS
        ):
            raise ValueError("venue history is duplicated or exceeds its bound")
        if len({f.fact_id for f in self.facts}) != len(self.facts):
            raise ValueError("venue fact identity repeats")
        previous = None
        for sequence, (command, ack) in enumerate(
            zip(self.commands, self.acknowledgments, strict=True), 1
        ):
            if (
                ack.sequence != sequence
                or ack.command_id != command.command_id
                or ack.command_sha256 != command.semantic_sha256
                or command.received_at > self.as_of
                or (previous is not None and command.received_at < previous)
            ):
                raise ValueError("venue acknowledgment or receipt history differs")
            previous = command.received_at
        if self.commands and self.as_of != self.commands[-1].received_at:
            raise ValueError("venue time differs from its latest receipt")


@dataclass(frozen=True, slots=True)
class VenueTransition(VenueRecord):
    state: VenueState
    acknowledgment: VenueAck


@dataclass(frozen=True, slots=True)
class VenueCommit(VenueRecord):
    model_sha256: str
    model_object: ObjectRef
    previous_state_sha256: str | None
    state_sha256: str
    state_object: ObjectRef
    acknowledgment: VenueAck | None

    def __post_init__(self) -> None:
        super(VenueCommit, self).__post_init__()
        require_digest(self.model_sha256, "venue commit model")
        if self.model_object.byte_count > MAX_VENUE_COMMAND_BYTES:
            raise ValueError("venue model object exceeds its bound")
        require_digest(self.state_sha256, "venue committed state")
        if self.previous_state_sha256 is not None:
            require_digest(self.previous_state_sha256, "previous venue state")
        if self.state_object.byte_count > MAX_VENUE_OBJECT_BYTES:
            raise ValueError("venue state object exceeds its bound")
        if (self.previous_state_sha256 is None) != (self.acknowledgment is None):
            raise ValueError("only the initial venue commit omits an acknowledgment")


@dataclass(frozen=True, slots=True)
class VenueReceipt(VenueRecord):
    acknowledgment: VenueAck
    journal_receipt: JournalReceipt

    def __post_init__(self) -> None:
        super(VenueReceipt, self).__post_init__()
        ack, receipt = self.acknowledgment, self.journal_receipt
        if (
            ack.command_id != receipt.command_id
            or ack.command_sha256 != receipt.command_sha256
            or ack.sequence + 1 != receipt.committed_head.sequence
            or receipt.committed_head.sequence != receipt.previous_head.sequence + 1
        ):
            raise ValueError("venue acknowledgment differs from its one-record receipt")


@dataclass(frozen=True, slots=True)
class VenueRead(VenueRecord):
    head: JournalHead
    state: VenueState

    def __post_init__(self) -> None:
        super(VenueRead, self).__post_init__()
        if self.head.sequence != self.state.sequence + 1:
            raise ValueError("venue checkpoint sequence differs from its journal head")


@dataclass(frozen=True, slots=True)
class VenueFactPage(VenueRecord):
    model_sha256: str
    state_sha256: str
    through_sequence: int
    offset: int
    facts: tuple[VenueFact, ...]
    next_offset: int
    complete: bool

    def __post_init__(self) -> None:
        super(VenueFactPage, self).__post_init__()
        require_digest(self.model_sha256, "venue page model")
        require_digest(self.state_sha256, "venue page source state")
        if (
            not 0 <= self.through_sequence <= MAX_VENUE_COMMANDS
            or not 0 <= self.offset <= self.next_offset <= MAX_VENUE_FACTS
            or self.next_offset != self.offset + len(self.facts)
            or len(self.facts) > 200
            or any(f.sequence > self.through_sequence for f in self.facts)
        ):
            raise ValueError("venue fact page is outside its fixed bounds")


class VerifiedVenueSources(Protocol):
    """Integration must resolve exact retained records and current dispatch authority.

    A risk decision alone is not dispatch permission. Implementations raise
    ValueError for unavailable, stale, mismatched or unqualified sources. The
    fixture implementation must declare synthetic provenance in the model.
    """

    def verify_submission(
        self, model: VenueModel, submit: VenueSubmit, *, received_at: datetime
    ) -> None: ...
    def verify_quote(
        self, model: VenueModel, source: ForwardSource, observation: ForwardObservation
    ) -> None: ...
