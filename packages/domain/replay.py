"""Deterministic availability-time replay and watermark-complete market batches."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise

from packages.domain.clock import Clock, FixedClock, SimulatedClock
from packages.domain.market_batch import (
    MarketBatch,
    MarketWatermark,
    ReplayRevisionPolicy,
    _batch_event_key,
    _create_market_batch,
    _event_semantics,
    _require_utc,
    _semantic_sha256,
    _watermark_semantics,
)
from packages.domain.models import MarketEvent

REPLAY_CONTRACT_VERSION = "phase2-replay-v1"


class ReplayContractError(ValueError):
    """The immutable replay tape cannot be interpreted without ambiguity."""


class ReplayIdentityConflict(ReplayContractError):
    """One immutable identity was reused for unequal semantics."""


class MarketEventConflict(ReplayContractError):
    """A decision slice has ambiguous or invalid market-event revisions."""


class UnexpectedMarketEvent(ReplayContractError):
    """A fact is outside the watermark-pinned decision scope."""


class LateMarketEvent(ReplayContractError):
    """A fact arrived after its decision slice was permanently sealed."""


@dataclass(frozen=True, slots=True)
class ReplayResult:
    started_at: datetime
    completed_at: datetime
    tape_sha256: str
    processed_event_ids: tuple[str, ...]
    batches: tuple[MarketBatch, ...]
    complete_batch_ids: tuple[str, ...]
    skipped_batch_ids: tuple[str, ...]

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            {
                "batch_sha256": [batch.semantic_sha256 for batch in self.batches],
                "complete_batch_ids": list(self.complete_batch_ids),
                "contract_version": REPLAY_CONTRACT_VERSION,
                "processed_event_ids": list(self.processed_event_ids),
                "skipped_batch_ids": list(self.skipped_batch_ids),
                "tape_sha256": self.tape_sha256,
            }
        )


type ReplayItem = MarketEvent | MarketWatermark
type CompleteBatchCallback = Callable[[MarketBatch, Clock], None]


def _replay_key(item: ReplayItem) -> tuple[object, ...]:
    if isinstance(item, MarketEvent):
        return (
            item.available_at,
            0,
            item.source,
            item.source_sequence is None,
            item.source_sequence or 0,
            "market",
            item.event_time,
            item.instrument_id,
            item.observation_key,
            item.revision,
            item.event_id,
        )
    return (
        item.closed_at,
        1,
        "",
        True,
        0,
        "watermark",
        item.event_time_through,
        "",
        item.watermark_id,
        0,
        item.watermark_id,
    )


def _unique_events(events: Iterable[MarketEvent]) -> tuple[MarketEvent, ...]:
    by_id: dict[str, MarketEvent] = {}
    for event in events:
        _require_utc(event.event_time, "event_time")
        _require_utc(event.available_at, "available_at")
        existing = by_id.get(event.event_id)
        if existing is None:
            by_id[event.event_id] = event
        elif existing != event:
            raise ReplayIdentityConflict(
                f"market event identity {event.event_id!r} has conflicting semantics"
            )
    observation_bindings: dict[tuple[str, str], tuple[str, datetime]] = {}
    for event in by_id.values():
        identity = (event.source, event.observation_key)
        binding = (event.instrument_id, event.event_time)
        existing_binding = observation_bindings.get(identity)
        if existing_binding is not None and existing_binding != binding:
            raise ReplayIdentityConflict(
                "market observation identity "
                f"{identity!r} is bound to multiple instrument/event-time chains"
            )
        observation_bindings[identity] = binding
    return tuple(by_id.values())


def _unique_watermarks(
    watermarks: Iterable[MarketWatermark],
) -> tuple[MarketWatermark, ...]:
    by_id: dict[str, MarketWatermark] = {}
    by_event_time: dict[datetime, MarketWatermark] = {}
    for watermark in watermarks:
        existing = by_id.get(watermark.watermark_id)
        if existing is not None:
            if existing != watermark:
                raise ReplayIdentityConflict(
                    f"watermark identity {watermark.watermark_id!r} has conflicting semantics"
                )
            continue
        same_slice = by_event_time.get(watermark.event_time_through)
        if same_slice is not None:
            raise ReplayContractError(
                "one replay tape cannot seal the same decision event time more than once"
            )
        by_id[watermark.watermark_id] = watermark
        by_event_time[watermark.event_time_through] = watermark
    if not by_id:
        raise ReplayContractError("replay requires at least one market watermark")
    ordered = tuple(
        sorted(
            by_id.values(),
            key=lambda watermark: (
                watermark.closed_at,
                watermark.event_time_through,
                watermark.watermark_id,
            ),
        )
    )
    for previous, current in pairwise(ordered):
        if current.event_time_through <= previous.event_time_through:
            raise ReplayContractError(
                "watermark event-time frontiers must strictly increase in closed-at order"
            )
    return ordered


def _select_events(
    events: tuple[MarketEvent, ...],
    watermark: MarketWatermark,
) -> tuple[MarketEvent, ...]:
    by_instrument: dict[str, list[MarketEvent]] = {}
    for event in events:
        by_instrument.setdefault(event.instrument_id, []).append(event)

    selected: list[MarketEvent] = []
    for instrument_id, instrument_events in by_instrument.items():
        observations = {event.observation_key for event in instrument_events}
        if len(observations) != 1:
            raise MarketEventConflict(
                f"instrument {instrument_id!r} has multiple observations in one decision slice"
            )
        by_revision: dict[int, MarketEvent] = {}
        for event in instrument_events:
            existing = by_revision.get(event.revision)
            if existing is not None and existing.event_id != event.event_id:
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} has conflicting revision {event.revision}"
                )
            by_revision[event.revision] = event
        revisions = tuple(sorted(by_revision))
        if revisions[0] != 1 or any(
            current != previous + 1 for previous, current in pairwise(revisions)
        ):
            raise MarketEventConflict(
                f"instrument {instrument_id!r} has a noncontiguous revision chain"
            )
        ordered = tuple(by_revision[revision] for revision in revisions)
        for previous, current in pairwise(ordered):
            if current.supersedes_event_revision_id != previous.event_id:
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} has a broken revision chain"
                )
            if current.source != previous.source:
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} changes source within a revision chain"
                )
            if current.available_at < previous.available_at:
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} has nonmonotonic revision availability"
                )
            if (previous.source_sequence is None) != (current.source_sequence is None):
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} changes source-sequence presence"
                )
            if (
                previous.source_sequence is not None
                and current.source_sequence is not None
                and current.source_sequence <= previous.source_sequence
            ):
                raise MarketEventConflict(
                    f"instrument {instrument_id!r} has nonmonotonic source sequence"
                )
        selected.append(
            ordered[0]
            if watermark.revision_policy is ReplayRevisionPolicy.FIRST_SEEN
            else ordered[-1]
        )
    return tuple(sorted(selected, key=_batch_event_key))


def replay_market_events(
    *,
    events: Iterable[MarketEvent],
    watermarks: Iterable[MarketWatermark],
    on_complete_batch: CompleteBatchCallback | None = None,
) -> ReplayResult:
    """Replay an immutable synthetic event tape through explicit watermarks.

    Input order never determines output. Every market fact at an availability
    instant is reduced before a watermark at that same instant. Only a complete
    batch invokes the callback; an incomplete batch is sealed and skipped.
    """

    unique_events = _unique_events(events)
    unique_watermarks = _unique_watermarks(watermarks)
    watermark_by_event_time = {
        watermark.event_time_through: watermark for watermark in unique_watermarks
    }
    for event in sorted(unique_events, key=_replay_key):
        watermark = watermark_by_event_time.get(event.event_time)
        if watermark is None:
            raise UnexpectedMarketEvent(
                f"market event {event.event_id!r} has no pinned decision watermark"
            )
        if event.instrument_id not in watermark.expected_instrument_ids:
            raise UnexpectedMarketEvent(
                f"market event {event.event_id!r} has an unexpected instrument"
            )
        if event.available_at > watermark.closed_at:
            raise LateMarketEvent(f"market event {event.event_id!r} arrived after its watermark")
    events_by_time: dict[datetime, list[MarketEvent]] = {}
    for event in unique_events:
        events_by_time.setdefault(event.event_time, []).append(event)
    for watermark in unique_watermarks:
        _select_events(
            tuple(events_by_time.get(watermark.event_time_through, [])),
            watermark,
        )
    queue_items: list[ReplayItem] = [*unique_events, *unique_watermarks]
    queue = tuple(sorted(queue_items, key=_replay_key))
    tape_sha256 = _semantic_sha256(
        {
            "contract_version": REPLAY_CONTRACT_VERSION,
            "events": [_event_semantics(event) for event in sorted(unique_events, key=_replay_key)],
            "watermarks": [
                _watermark_semantics(watermark)
                for watermark in sorted(unique_watermarks, key=_replay_key)
            ],
        }
    )
    first_item = queue[0]
    started_at = (
        first_item.available_at if isinstance(first_item, MarketEvent) else first_item.closed_at
    )
    clock = SimulatedClock(started_at)
    buffered: dict[datetime, list[MarketEvent]] = {}
    closed_event_times: set[datetime] = set()
    processed_event_ids: list[str] = []
    batches: list[MarketBatch] = []
    complete_batch_ids: list[str] = []
    skipped_batch_ids: list[str] = []

    for item in queue:
        item_available_at = item.available_at if isinstance(item, MarketEvent) else item.closed_at
        clock.advance_to(item_available_at)
        if isinstance(item, MarketEvent):
            watermark = watermark_by_event_time.get(item.event_time)
            if watermark is None:
                raise UnexpectedMarketEvent(
                    f"market event {item.event_id!r} has no pinned decision watermark"
                )
            if item.instrument_id not in watermark.expected_instrument_ids:
                raise UnexpectedMarketEvent(
                    f"market event {item.event_id!r} has an unexpected instrument"
                )
            if item.event_time in closed_event_times:
                raise LateMarketEvent(f"market event {item.event_id!r} arrived after its watermark")
            buffered.setdefault(item.event_time, []).append(item)
            processed_event_ids.append(item.event_id)
            continue

        selected = _select_events(
            tuple(buffered.pop(item.event_time_through, [])),
            item,
        )
        batch = _create_market_batch(watermark=item, events=selected)
        batches.append(batch)
        closed_event_times.add(item.event_time_through)
        if batch.complete:
            complete_batch_ids.append(batch.batch_id)
            if on_complete_batch is not None:
                on_complete_batch(batch, FixedClock(clock.now()))
        else:
            skipped_batch_ids.append(batch.batch_id)

    return ReplayResult(
        started_at=started_at,
        completed_at=clock.now(),
        tape_sha256=tape_sha256,
        processed_event_ids=tuple(processed_event_ids),
        batches=tuple(batches),
        complete_batch_ids=tuple(complete_batch_ids),
        skipped_batch_ids=tuple(skipped_batch_ids),
    )
