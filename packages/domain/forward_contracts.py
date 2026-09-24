"""Immutable forward-data evidence; these records never authorize execution.

Source qualification fields are declarations to validate against an integration
port's retained evidence. Their presence is not proof of provider entitlement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar, Literal

from packages.domain.engine_contracts import DailyPrice
from packages.domain.personal_contracts import (
    ContractRecord,
    require_amount,
    require_digest,
    require_text,
)

type ForwardKind = Literal["daily", "quote"]
type ForwardMode = Literal["recorded", "modeled"]
type SourceEnvironment = Literal["production", "sandbox", "synthetic"]


class ForwardRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-forward-data/1"


@dataclass(frozen=True, slots=True)
class ForwardSource(ForwardRecord):
    source_id: str
    provider: Literal["tiingo", "etrade", "fixture"]
    environment: SourceEnvironment
    account_scope: str | None
    identity_reference: str | None
    rights_status: Literal["allowed", "denied", "unknown"]
    rights_reference: str | None
    entitlement_status: Literal["realtime", "delayed", "not_required", "unknown"]
    entitlement_reference: str | None
    sequence_scope: str | None = None
    sequence_start: int | None = None
    sequence_reference: str | None = None

    def __post_init__(self) -> None:
        super(ForwardSource, self).__post_init__()
        require_text(self.source_id, "source ID")
        for field in (
            "account_scope",
            "identity_reference",
            "rights_reference",
            "entitlement_reference",
            "sequence_scope",
            "sequence_reference",
        ):
            if (value := getattr(self, field)) is not None:
                require_text(value, field)
        if (self.provider == "fixture") != (self.environment == "synthetic"):
            raise ValueError("fixture and provider source environments must remain separate")
        if self.provider == "tiingo" and self.environment != "production":
            raise ValueError("Tiingo source has no admitted sandbox profile")
        sequence = (self.sequence_scope, self.sequence_start, self.sequence_reference)
        if any(v is not None for v in sequence) and any(v is None for v in sequence):
            raise ValueError("sequence continuity needs scope, start and evidence")
        if self.sequence_start is not None and not 0 <= self.sequence_start < 2**63:
            raise ValueError("source sequence is outside its range")


@dataclass(frozen=True, slots=True)
class CaptureReceipt(ForwardRecord):
    """One successfully received and validated raw object, not a HTTP success claim."""

    capture_id: str
    source_sha256: str
    request_sha256: str
    raw_sha256: str
    byte_count: int
    requested_at: datetime
    received_at: datetime
    validated_at: datetime
    boot_id: str
    requested_monotonic_ns: int
    received_monotonic_ns: int
    validated_monotonic_ns: int

    def __post_init__(self) -> None:
        super(CaptureReceipt, self).__post_init__()
        require_text(self.capture_id, "capture ID")
        require_text(self.boot_id, "clock boot ID")
        for field in ("source_sha256", "request_sha256", "raw_sha256"):
            require_digest(getattr(self, field), field)
        if not 0 < self.byte_count <= 32 * 1024 * 1024:
            raise ValueError("capture object exceeds its byte bounds")
        if not self.requested_at <= self.received_at <= self.validated_at:
            raise ValueError("capture UTC times regressed")
        if not (
            0
            <= self.requested_monotonic_ns
            <= self.received_monotonic_ns
            <= self.validated_monotonic_ns
            < 2**63
        ):
            raise ValueError("capture monotonic times regressed or exceed their range")


@dataclass(frozen=True, slots=True)
class ModeledAvailability(ForwardRecord):
    available_at: datetime
    assumption_id: str

    def __post_init__(self) -> None:
        super(ModeledAvailability, self).__post_init__()
        require_text(self.assumption_id, "availability assumption")


@dataclass(frozen=True, slots=True)
class ForwardQuote(ForwardRecord):
    instrument_id: str
    symbol: str
    session: date
    bid: Decimal | None
    ask: Decimal | None
    source_at: datetime | None
    currency: str | None
    delay_status: Literal["realtime", "delayed", "unknown"]
    bid_at: datetime | None = None
    ask_at: datetime | None = None
    time_basis: Literal["documented_side_times", "unknown"] = "unknown"

    def __post_init__(self) -> None:
        super(ForwardQuote, self).__post_init__()
        require_text(self.instrument_id, "instrument ID")
        if self.symbol not in ("DIA", "IWM", "QQQ", "SPY"):
            raise ValueError("unsupported forward instrument")
        if self.currency is not None:
            require_text(self.currency, "quote currency")
        for name in ("bid", "ask"):
            if (value := getattr(self, name)) is not None:
                require_amount(value, name, positive=True)
        if self.bid is not None and self.ask is not None and self.bid > self.ask:
            raise ValueError("crossed quote cannot be normalized")


@dataclass(frozen=True, slots=True)
class ForwardObservation(ForwardRecord):
    observation_id: str
    source_id: str
    payload: DailyPrice | ForwardQuote
    availability: CaptureReceipt | ModeledAvailability
    revision_key: str
    revision: int = 1
    predecessor_id: str | None = None
    source_sequence: int | None = None

    def __post_init__(self) -> None:
        super(ForwardObservation, self).__post_init__()
        for name in ("observation_id", "source_id", "revision_key"):
            require_text(getattr(self, name), name)
        if not 1 <= self.revision <= 100000:
            raise ValueError("revision is outside the retained observation bound")
        if (self.revision == 1) != (self.predecessor_id is None):
            raise ValueError("revision requires exactly one predecessor except at its root")
        if self.predecessor_id is not None:
            require_text(self.predecessor_id, "predecessor ID")
            if self.predecessor_id == self.observation_id:
                raise ValueError("observation cannot precede itself")
        if self.source_sequence is not None and not 0 <= self.source_sequence < 2**63:
            raise ValueError("source sequence is outside its range")

    @property
    def known_at(self) -> datetime:
        availability = self.availability
        return (
            availability.validated_at
            if isinstance(availability, CaptureReceipt)
            else availability.available_at
        )

    @property
    def kind(self) -> ForwardKind:
        return "quote" if isinstance(self.payload, ForwardQuote) else "daily"


@dataclass(frozen=True, slots=True)
class ForwardRequirement(ForwardRecord):
    source_id: str
    instrument_id: str
    symbol: str
    session: date
    kind: ForwardKind

    def __post_init__(self) -> None:
        super(ForwardRequirement, self).__post_init__()
        require_text(self.source_id, "required source")
        require_text(self.instrument_id, "required instrument")
        if self.symbol not in ("DIA", "IWM", "QQQ", "SPY"):
            raise ValueError("unsupported required instrument")


@dataclass(frozen=True, slots=True)
class ForwardFrontier(ForwardRecord):
    frontier_id: str
    requirements: tuple[ForwardRequirement, ...]
    cutoff: datetime
    closed_at: datetime
    source_head_sha256: str
    selected: tuple[tuple[str, str], ...]
    missing: tuple[tuple[str, tuple[str, ...]], ...]
    status: Literal["complete", "skipped"]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(ForwardFrontier, self).__post_init__()
        require_text(self.frontier_id, "frontier ID")
        require_digest(self.source_head_sha256, "frontier source head")
        expected = tuple(r.semantic_sha256 for r in self.requirements)
        if not 1 <= len(expected) <= 16 or len(set(expected)) != len(expected):
            raise ValueError("frontier needs bounded unique requirements")
        selected = tuple(k for k, _ in self.selected)
        missing = tuple(k for k, _ in self.missing)
        if len(set((*selected, *missing))) != len(expected) or set((*selected, *missing)) != set(
            expected
        ):
            raise ValueError("frontier selected/missing partition differs from requirements")
        if self.status == "complete" and (
            self.missing or self.closed_at >= self.cutoff or self.reasons
        ):
            raise ValueError("complete frontier requires pre-cutoff complete evidence")
        if self.status == "skipped" and (self.closed_at < self.cutoff or not self.reasons):
            raise ValueError("skipped frontier requires cutoff and reasons")


@dataclass(frozen=True, slots=True)
class ForwardDataState(ForwardRecord):
    sources: tuple[ForwardSource, ...]
    mode: ForwardMode
    observations: tuple[ForwardObservation, ...] = ()
    frontiers: tuple[ForwardFrontier, ...] = ()

    def __post_init__(self) -> None:
        super(ForwardDataState, self).__post_init__()
        ids = tuple(s.source_id for s in self.sources)
        if not 1 <= len(ids) <= 8 or ids != tuple(sorted(set(ids))):
            raise ValueError("sources must be bounded sorted unique profiles")
        if any((s.provider == "fixture") != (self.mode == "modeled") for s in self.sources):
            raise ValueError("recorded and modeled source profiles cannot be mixed")
        obs_ids = tuple(o.observation_id for o in self.observations)
        if len(obs_ids) > 100000 or obs_ids != tuple(sorted(set(obs_ids))):
            raise ValueError("retained observations must be bounded sorted unique")
        sources = {s.source_id: s for s in self.sources}
        by_id = {o.observation_id: o for o in self.observations}
        revisions: set[tuple[str, str, int]] = set()
        sequences: set[tuple[str, int]] = set()
        captures: dict[str, CaptureReceipt] = {}
        for observation in self.observations:
            source = sources.get(observation.source_id)
            if source is None:
                raise ValueError("observation source is not pinned")
            availability = observation.availability
            if self.mode == "recorded":
                if (
                    not isinstance(availability, CaptureReceipt)
                    or availability.source_sha256 != source.semantic_sha256
                ):
                    raise ValueError("capture source/mode differs")
            elif not isinstance(availability, ModeledAvailability):
                raise ValueError("modeled source requires modeled availability")
            revision_key = (observation.source_id, observation.revision_key, observation.revision)
            if revision_key in revisions:
                raise ValueError("revision chain forks")
            revisions.add(revision_key)
            if observation.source_sequence is not None:
                sequence_key = (observation.source_id, observation.source_sequence)
                if (
                    source.sequence_start is None
                    or observation.source_sequence < source.sequence_start
                    or sequence_key in sequences
                ):
                    raise ValueError("source sequence scope/conflict differs")
                sequences.add(sequence_key)
            if isinstance(availability, CaptureReceipt):
                if (
                    availability.capture_id in captures
                    and captures[availability.capture_id] != availability
                ):
                    raise ValueError("capture identity conflicts")
                captures[availability.capture_id] = availability
            parent = by_id.get(observation.predecessor_id or "")
            if parent is not None and (
                parent.source_id != observation.source_id
                or parent.revision_key != observation.revision_key
                or parent.revision + 1 != observation.revision
                or (
                    parent.kind,
                    parent.payload.instrument_id,
                    parent.payload.symbol,
                    parent.payload.session,
                )
                != (
                    observation.kind,
                    observation.payload.instrument_id,
                    observation.payload.symbol,
                    observation.payload.session,
                )
                or (
                    parent.source_sequence is not None
                    and observation.source_sequence is not None
                    and parent.source_sequence >= observation.source_sequence
                )
            ):
                raise ValueError("revision predecessor differs")
        frontier_ids = tuple(f.frontier_id for f in self.frontiers)
        if len(frontier_ids) > 10000 or len(set(frontier_ids)) != len(frontier_ids):
            raise ValueError("closed frontier identities must be bounded unique")
        if any(
            a.closed_at > b.closed_at
            for a, b in zip(self.frontiers, self.frontiers[1:], strict=False)
        ):
            raise ValueError("frontier closure time regressed")
        for frontier in self.frontiers:
            for requirement_id, observation_id in frontier.selected:
                selected_observation = by_id.get(observation_id)
                requirement = next(
                    r for r in frontier.requirements if r.semantic_sha256 == requirement_id
                )
                if (
                    selected_observation is None
                    or (
                        selected_observation.source_id,
                        selected_observation.payload.instrument_id,
                        selected_observation.payload.symbol,
                        selected_observation.payload.session,
                        selected_observation.kind,
                    )
                    != (
                        requirement.source_id,
                        requirement.instrument_id,
                        requirement.symbol,
                        requirement.session,
                        requirement.kind,
                    )
                    or selected_observation.known_at > frontier.closed_at
                    or selected_observation.known_at >= frontier.cutoff
                ):
                    raise ValueError("frontier selected observation differs")


@dataclass(frozen=True, slots=True)
class ForwardDataTransition(ForwardRecord):
    state: ForwardDataState
    disposition: Literal["accepted", "pending", "duplicate", "rejected", "closed"]
    reasons: tuple[str, ...] = ()
    frontier: ForwardFrontier | None = None


@dataclass(frozen=True, slots=True)
class QuoteAdmission(ForwardRecord):
    observation_sha256: str
    source_sha256: str
    evaluated_at: datetime
    eligible: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        super(QuoteAdmission, self).__post_init__()
        require_digest(self.observation_sha256, "quote observation")
        require_digest(self.source_sha256, "quote source")
        if self.eligible == bool(self.reasons):
            raise ValueError("quote eligibility and reasons disagree")
